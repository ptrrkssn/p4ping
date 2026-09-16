#ifndef P4PING_NTP_H
#define P4PING_NTP_H 1

struct ntp_timestamp {
    uint32_t seconds;
    uint32_t fraction;
} __attribute__((packed));

struct ntp_header {
    unsigned mode : 3;
    unsigned vn : 3;
    unsigned li : 2;

    uint8_t stratum;
    uint8_t poll;
    uint8_t precision;

    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t reference_id;

    struct ntp_timestamp reference_timestamp;
    struct ntp_timestamp origin_timestamp;
    struct ntp_timestamp receive_timestamp;
    struct ntp_timestamp transmit_timestamp;
} __attribute__((packed));

extern int
ntp_send_request(struct target *tp,
                 unsigned int *seq);

extern int
ntp_validate_reply(struct target *tp,
                   unsigned int seq,
                   struct timespec *t,
                   void *buf,
                   size_t buflen);
#endif
