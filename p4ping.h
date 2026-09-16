#ifndef P4PING_H
#define P4PING_H 1

#include <time.h>

#include <sys/socket.h>
#include <netdb.h>

#include "buffer.h"

typedef struct target {
    int fd;
    char *addr;
    char *name;
    struct addrinfo *ai;
    struct timespec t0;
    struct timespec t1;
    struct {
        unsigned long sent;
        unsigned long missed;
    } packets;
    struct {
        double min;
        double max;
        double sum;
    } rtt;
    struct target *next;
    BUFFER *buf;
} TARGET;

extern char *version;
extern char *argv0;

extern char *f_payload;

extern int f_verbose;

extern uint16_t f_ident;

#endif
