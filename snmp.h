#ifndef P4PING_SNMP_H
#define P4PING_SNMP_H 1

#include <time.h>
#include <sys/types.h>

#include "p4ping.h"

extern int
snmp_send_request(struct target *tp,
                  unsigned int *seq);

extern int
snmp_validate_reply(struct target *tp,
                    unsigned int seq,
                    struct timespec *t,
                    void *rbuf,
                    size_t rbuflen);

#endif
