#ifndef P4PING_DNS_H
#define P4PING_DNS_H 1

#include <sys/types.h>

struct dns_header {
    uint16_t id;

    unsigned rd     : 1;
    unsigned tc     : 1;
    unsigned aa     : 1;
    unsigned opcode : 4;
    unsigned qr     : 1;

    unsigned rcode  : 4;
    unsigned z      : 3;
    unsigned ra     : 1;

    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));


struct dns_request {
    struct dns_header h;
    unsigned char b[16384];
} __attribute__ ((packed));

struct dns_reply {
    struct dns_header h;
    unsigned char b[];
} __attribute__ ((packed));


extern int
dns_udp_send_request(struct target *tp,
                     unsigned int *seq);

extern int
dns_tcp_send_request(struct target *tp,
                     unsigned int *seq);

extern int
dns_udp_validate_reply(struct target *tp,
                       unsigned int seq,
                       struct timespec *t,
                       void *buf,
                       size_t buflen);

extern int
dns_tcp_validate_reply(struct target *tp,
                       unsigned int seq,
                       struct timespec *t,
                       void *buf,
                       size_t buflen);

#endif
