#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <math.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include "checksum.h"

#define packet_buffer_size 10
#define translation_port_size 2001

struct address_tuple
{
    char internal_ip[16];
    char external_ip[16];
    uint16_t internal_port;
    uint16_t external_port;
    time_t t;
};

struct nat_mapping
{
    struct address_tuple *entry;
    int available[translation_port_size];
};

struct nfq_handle *nfqueueHandler;
struct nfq_q_handle *queueHandler;
struct nat_mapping *translation_table;
int nfqueue_fd;

char *nat_ip, *local_network;
int subnet_mask, bucket_size, fill_rate;

struct nfq_data *packet_buffer[packet_buffer_size];
int packet_buffer_count = 0;
pthread_mutex_t packet_buffer_mutex;

int token_bucket = 0;
time_t previous;

void printTable()
{
    printf("         Source          |         Translated        \n");
    printf("*************************|***************************\n");
    for (int i = 0; i < translation_port_size; i++)
    {
        if (translation_table->available[i] == false)
        {
            printf(" (%s, %d)      | (%s, %d)\n",
                   translation_table->entry[i].internal_ip,
                   translation_table->entry[i].internal_port,
                   translation_table->entry[i].external_ip,
                   translation_table->entry[i].external_port);
        }
    }
    printf("*************************|***************************\n\n");
}

void gen_token()
{
    time_t current;
    time(&current);

    int token_generated = (current - previous) * fill_rate;

    if (token_bucket + token_generated > bucket_size)
        token_bucket = bucket_size;
    else
        token_bucket += token_generated;

    previous = current;
}

int getSmallestAvailable()
{
    for (int i = 0; i < translation_port_size; i++)
        if (translation_table->available[i])
            return i;
    return -1;
}

void createEntry(int index, char internal_ip[], uint16_t internal_port)
{
    strcpy(translation_table->entry[index].internal_ip, internal_ip);
    translation_table->entry[index].internal_port = internal_port;
    time_t current;
    time(&current);
    translation_table->entry[index].t = current;
    translation_table->available[index] = 0;
    printTable();
}

void clearExpired()
{
    int updated = 0;
    time_t current;
    time(&current);
    for (int i = 0; i < translation_port_size; i++)
    {
        if (!translation_table->available[i] && current - translation_table->entry[i].t > 10)
        {
            translation_table->available[i] = 1;
            updated = 1;
        }
    }
    if (updated)
        printTable();
}

int checkEntryOutbound(char internal_ip[], uint16_t internal_port)
{
    for (int i = 0; i < translation_port_size; i++)
    {
        if (!translation_table->available[i] &&
            strcmp(internal_ip, translation_table->entry[i].internal_ip) == 0 &&
            internal_port == translation_table->entry[i].internal_port)
            return i;
    }
    return -1;
}

int checkEntryInbound(uint16_t external_port)
{
    int index = external_port - 10000;
    return !translation_table->available[index] ? index : -1;
}

struct nfq_data *dequeuePacketBuffer()
{
    pthread_mutex_lock(&packet_buffer_mutex);
    struct nfq_data *pkt = packet_buffer[0];
    for (int i = 0; i < packet_buffer_count - 1; i++)
        packet_buffer[i] = packet_buffer[i + 1];
    packet_buffer_count--;
    pthread_mutex_unlock(&packet_buffer_mutex);
    return pkt;
}

char *IP2String(uint32_t original)
{
    char *str = (char *)malloc(sizeof(char) * 16);
    int a = original % 256;
    int b = (original / 256) % 256;
    int c = ((original / 256) / 256) % 256;
    int d = original / (256 * 256 * 256);
    sprintf(str, "%d.%d.%d.%d", a, b, c, d);
    return str;
}

uint32_t String2IP(char *str)
{
    char *tmp = (char *)malloc(sizeof(char) * 16);
    strcpy(tmp, str);
    char *tok = strtok(tmp, ".");
    int count = 3;
    uint32_t ip = 0;
    while (tok != NULL)
    {
        ip += atoi(tok) * pow(256, count);
        count--;
        tok = strtok(NULL, ".");
    }
    return ip;
}

void source_modify(unsigned char *pktData, int index)
{
    struct iphdr *ipHeader = (struct iphdr *)pktData;
    struct udphdr *udph = (struct udphdr *)(((char *)ipHeader) + ipHeader->ihl * 4);

    // modify source
    ipHeader->saddr = htonl(String2IP(translation_table->entry[index].external_ip));
    udph->source = htons(translation_table->entry[index].external_port);

    // update checksum
    udph->check = udp_checksum(pktData);
    ipHeader->check = ip_checksum((unsigned char *)ipHeader);
}

void dest_modify(unsigned char *pktData, int index)
{
    struct iphdr *ipHeader = (struct iphdr *)pktData;
    struct udphdr *udph = (struct udphdr *)(((char *)ipHeader) + ipHeader->ihl * 4);

    // modify destination
    ipHeader->daddr = htonl(String2IP(translation_table->entry[index].internal_ip));
    udph->dest = htons(translation_table->entry[index].internal_port);

    // update checksum
    udph->check = udp_checksum(pktData);
    ipHeader->check = ip_checksum((unsigned char *)ipHeader);
}

void *packetHandler()
{
    unsigned char *pktData;
    while (1)
    {
        if (packet_buffer_count)
        {
            clearExpired();

            struct nfq_data *pkt = dequeuePacketBuffer();
            struct nfqnl_msg_packet_hdr *header;
            if (!(header = nfq_get_msg_packet_hdr(pkt)))
            {
                fprintf(stderr, "Error: nfq_get_msg_packet_hdr()\n");
                continue;
            }

            u_int32_t id = ntohl(header->packet_id);
            int ip_pkt_len = nfq_get_payload(pkt, &pktData);
            struct iphdr *ipHeader = (struct iphdr *)pktData;
            if (ipHeader->protocol != IPPROTO_UDP)
            {
                nfq_set_verdict(queueHandler, id, NF_DROP, ip_pkt_len, pktData);
                continue;
            }

            char *source = IP2String(ipHeader->saddr);
            char *dest = IP2String(ipHeader->daddr);
            struct udphdr *udph = (struct udphdr *)(((char *)ipHeader) + ipHeader->ihl * 4);
            uint16_t internal_port = ntohs(udph->source);
            unsigned int local_mask = 0xffffffff << (32 - subnet_mask);

            if ((ntohl(ipHeader->saddr) & local_mask) == String2IP(local_network))
            {
                // outbound traffic
                int index = checkEntryOutbound(source, internal_port);
                if (index == -1)
                {
                    index = getSmallestAvailable();
                    createEntry(index, source, internal_port);
                }
                source_modify(pktData, index);
                time_t t;
                time(&t);
                translation_table->entry[index].t = t;
            }
            else
            {
                // inbound traffic
                int index = checkEntryInbound(ntohs(udph->dest));
                if (index != -1)
                {
                    dest_modify(pktData, index);
                    time_t t;
                    time(&t);
                    translation_table->entry[index].t = t;
                }
                else
                {
                    nfq_set_verdict(queueHandler, id, NF_DROP, ip_pkt_len, pktData);
                    continue;
                }
            }

            // wait for token
            gen_token();
            if (token_bucket > 0)
            {
                nfq_set_verdict(queueHandler, id, NF_ACCEPT, ip_pkt_len, pktData);
                token_bucket--;
            }
            else
            {
                while (1)
                {
                    usleep(1000000 / fill_rate);
                    gen_token();
                    if (token_bucket > 0)
                    {
                        nfq_set_verdict(queueHandler, id, NF_ACCEPT, ip_pkt_len, pktData);
                        token_bucket--;
                        break;
                    }
                }
            }
            free(source);
            free(dest);
        }
        usleep(100);
    }
    pthread_exit(NULL);
}

static int callback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *pkt, void *data)
{
    if (packet_buffer_count < packet_buffer_size)
    {
        pthread_mutex_lock(&packet_buffer_mutex);
        packet_buffer[packet_buffer_count++] = pkt;
        pthread_mutex_unlock(&packet_buffer_mutex);
        return 1;
    }
    return 0;
}

void initHandler(int *nfq_fd)
{
    if (!(nfqueueHandler = nfq_open()))
    {
        fprintf(stderr, "Error: nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(nfqueueHandler, AF_INET) < 0)
    {
        fprintf(stderr, "Error: nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(nfqueueHandler, AF_INET) < 0)
    {
        fprintf(stderr, "Error: nfq_bind_pf()\n");
        exit(1);
    }

    if (!(queueHandler = nfq_create_queue(nfqueueHandler, 0, &callback, NULL)))
    {
        fprintf(stderr, "Error: nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(queueHandler, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    struct nfnl_handle *netlinkHandle = nfq_nfnlh(nfqueueHandler);
    *nfq_fd = nfnl_fd(netlinkHandle);
}

int main(int argc, char **argv)
{
    time(&previous);
    char buf[4096];
    int res;

    if (argc != 6)
    {
        fprintf(stderr, "Usage: sudo ./nat <IP> <LAN> <MASK> <bucket size> <fill rate>\n");
        exit(1);
    }
    nat_ip = argv[1];
    local_network = argv[2];
    subnet_mask = atoi(argv[3]);
    bucket_size = atoi(argv[4]);
    fill_rate = atoi(argv[5]);

    pthread_t packet_tid;
    pthread_create(&packet_tid, NULL, packetHandler, NULL);
    pthread_mutex_init(&packet_buffer_mutex, NULL);

    translation_table = (struct nat_mapping *)malloc(sizeof(struct nat_mapping));
    translation_table->entry = (struct address_tuple *)malloc(sizeof(struct address_tuple) * translation_port_size);
    for (int i = 0; i < translation_port_size; i++)
    {
        strcpy(translation_table->entry[i].external_ip, nat_ip);
        translation_table->entry[i].external_port = 10000 + i;
        translation_table->available[i] = 1;
    }
    initHandler(&nfqueue_fd);

    while ((res = recv(nfqueue_fd, buf, sizeof(buf), 0)) && res >= 0)
        nfq_handle_packet(nfqueueHandler, buf, res);

    nfq_destroy_queue(queueHandler);
    nfq_close(nfqueueHandler);

    pthread_join(packet_tid, NULL);

    return 0;
}