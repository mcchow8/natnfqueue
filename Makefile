CC = gcc
CFLAGS = -O2 -Wall -std=gnu99
LIBS = -lpthread -lnetfilter_queue -lnfnetlink -lm
OBJS = checksum.o

%.o: %.c $.h
	$(CC) $(CFLAGS) -c $< -o $@

all: nat

nat: nat.c $(OBJS)
	${CC} $(CFLAGS) -o $@ nat.c $(OBJS) ${LIBS} 

clean:
	rm *.o nat