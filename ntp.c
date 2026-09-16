/*
 * ntp.c
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

#include "p4ping.h"
#include "ntp.h"


int
ntp_send_request(struct target *tp,
                 unsigned int *seq) {
    struct ntp_header tbuf;
    struct timespec tsb;

    memset(&tbuf, 0, sizeof(tbuf));

    tbuf.li = 0;
    tbuf.vn = 3;
    tbuf.mode = 3;

    clock_gettime(CLOCK_REALTIME, &tsb);
    tbuf.transmit_timestamp.seconds = htonl(tsb.tv_sec+2208988800);
    tbuf.transmit_timestamp.fraction = htonl(tsb.tv_nsec * 4294967296 / 1000000000);

    return sendto(tp->fd, (void *) &tbuf, sizeof(tbuf), 0, tp->ai->ai_addr, tp->ai->ai_addrlen);
}


#if 0
static double
timespec2double(struct timespec *tsp) {
    double d;

    d = tsp->tv_sec+(tsp->tv_nsec/1000000000.0);
    return d;
}
#endif

static double
ntp_timestamp2double(struct ntp_timestamp *ntp) {
    return htonl(ntp->seconds)-2208988800 + ntohl(ntp->fraction) / 4294967295.0;
}


static char *
ntp_timestamp2str(char *buf,
                  size_t bufsize,
                  struct ntp_timestamp *ntp) {
    time_t bt;
    struct tm *tmp;
    int len;
    double frac;
    char *bp = buf;


    bt = ntohl(ntp->seconds)-2208988800;
    tmp = localtime(&bt);

    strftime(bp, bufsize, "%Y-%m-%d %H:%M:%S", tmp);
    len = strlen(bp);
    bp += len;
    bufsize -= len;

    frac = ntohl(ntp->fraction) / 4294967295.0;
    snprintf(bp, bufsize, "%+f", frac);
    return buf;
}

int
ntp_validate_reply(struct target *tp,
                   unsigned int seq,
                   struct timespec *t,
                   void *buf,
                   size_t buflen) {
    char refbuf[128], origin[128], receive[128], transmit[128];
    struct ntp_header *np = (struct ntp_header *) buf;
    double delta;

    if (buflen < sizeof(*np))
        return -1;

    delta = ntp_timestamp2double(&np->origin_timestamp)-ntp_timestamp2double(&np->transmit_timestamp);

    if (f_verbose)
        fprintf(stderr, "NTP: li=%u, vn=%u, mode=%u, stratum=%u, poll=%u, precision=%u; root delay=%u, dispersion=%u, id=%u; reference=%s, origin=%s, receive=%s, transmit=%s; delta=%+f\n",
                np->li,
                np->vn,
                np->mode,
                np->stratum,
                np->poll,
                np->precision,
                ntohl(np->root_delay),
                ntohl(np->root_dispersion),
                ntohl(np->reference_id),
                ntp_timestamp2str(refbuf, sizeof(refbuf), &np->reference_timestamp),
                ntp_timestamp2str(origin, sizeof(origin), &np->origin_timestamp),
                ntp_timestamp2str(receive, sizeof(receive), &np->receive_timestamp),
                ntp_timestamp2str(transmit, sizeof(transmit), &np->transmit_timestamp),
                delta);

    return 0;
}
