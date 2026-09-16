#ifndef P4PING_ICMP_H
#define P4PING_ICMP_H 1

struct icmp_echo_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t ident;
    uint16_t seq;
};

#define MAXBUFSIZE 16384

struct icmp_echo {
    struct icmp_echo_header header;
    uint8_t payload[MAXBUFSIZE];
};


extern int
icmp_send_echo_request(struct target *tp,
                       unsigned int *seq);

extern int
icmp_validate_echo_reply(struct target *tp,
                         unsigned int seq,
                         struct timespec *t,
                         void *buf,
                         size_t buflen);

#endif
