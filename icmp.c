/*
 * snmp.c
 *
 * Copyright (c) 2023-2026 Peter Eriksson <pen@lysator.liu.se>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdio.h>

#include <sys/socket.h>
#ifdef HAVE_LINUX_ICMP_H
#include <linux/icmp.h>
#else
#include <netinet/ip_icmp.h>
#endif
#include <netinet/icmp6.h>

#include "p4ping.h"
#include "icmp.h"


static char *d_payload = "[p4ping]";


static unsigned int
calc_checksum(unsigned char *buf,
              size_t buflen) {
    uint32_t checksum = 0;
    unsigned char* end = buf + buflen;
    uint32_t carry;

    if (buflen % 2 == 1) {
        end = buf + buflen - 1;
        checksum += (*end) << 8;
    }

    while (buf < end) {
        checksum += buf[0] << 8;
        checksum += buf[1];
        buf += 2;
    }

    carry = checksum >> 16;
    while (carry) {
        checksum = (checksum & 0xffff) + carry;
        carry = checksum >> 16;
    }

    checksum = ~checksum;
    return checksum & 0xffff;
}


int
icmp_send_echo_request(struct target *tp,
                       unsigned int *seq) {
    struct icmp_echo ep;
    size_t plen, eplen;
    uint16_t xs = (*seq & 0xFFFF);
    char *payload = f_payload ? f_payload : d_payload;


    plen = strlen(payload);
    eplen = sizeof(struct icmp_echo_header)+plen;

    memset(&ep, 0, sizeof(ep));
    ep.header.type = (tp->ai->ai_family == AF_INET ? ICMP_ECHO : ICMP6_ECHO_REQUEST);
    ep.header.code = 0;
    ep.header.ident = htons(f_ident);
    ep.header.seq = htons(xs);

    memcpy(ep.payload, payload, plen);

    /* The kernel automatically calculates the checksum for ICMPV6 */
    if (tp->ai->ai_protocol == IPPROTO_ICMP)
        ep.header.checksum = htons(calc_checksum((unsigned char *) &ep, eplen));

    return sendto(tp->fd, &ep, eplen, 0, tp->ai->ai_addr, tp->ai->ai_addrlen);
}

int
icmp_validate_echo_reply(struct target *tp,
                         unsigned int seq,
                         struct timespec *t,
                         void *buf,
                         size_t buflen) {
    struct icmp_echo *er = (struct icmp_echo *) buf;
    uint16_t checksum;
    char *payload = f_payload ? f_payload : d_payload;
    size_t erlen = sizeof(struct icmp_echo_header)+strlen(payload);


    if (buflen < sizeof(struct icmp_echo_header))
        return -1;

    if (er->header.type != (tp->ai->ai_protocol == IPPROTO_ICMP ? ICMP_ECHOREPLY : ICMP6_ECHO_REPLY))
        return -2; /* Not an ICMP Echo Reply Message */

    if (buflen != erlen)
        return -3; /* Invalid packet length */

    /* Only validate the checksum for IPv4 */
    if (tp->ai->ai_protocol == IPPROTO_ICMP) {
        checksum = ntohs(er->header.checksum);
        er->header.checksum = 0;
        if (checksum != calc_checksum((unsigned char *) er, erlen)) {
            return -4; /* Invalid checksum */
        }
    }

    if (ntohs(er->header.ident) != f_ident)
        return -5; /* Invalid ident - not a response to our request */

    if (ntohs(er->header.seq) != (seq & 0xFFFF))
        return -6; /* Sequence number out of order */

    if (memcmp(er->payload, payload, strlen(payload)) != 0)
        return -7; /* Invalid payload content */

    return er->header.code;
}
