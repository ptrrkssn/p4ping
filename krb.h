#ifndef P4PING_KRB_H
#define P4PING_KRB_H 1

#include <stdint.h>
#include <time.h>
#include "p4ping.h"

extern int
krb_send_request(struct target *tp,
                 unsigned int *seq);

extern int
krb_validate_reply(struct target *tp,
                   unsigned int seq,
                   struct timespec *t,
                   void *rbuf,
                   size_t rbuflen);

#endif
