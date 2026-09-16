/*
 * dns.c
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
#include <ctype.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>

#include "p4ping.h"
#include "dns.h"


struct dns_mapping {
    char *s;
    int v;
};

static struct dns_mapping dns_types[] = {
    { "A", T_A },
    { "AAAA", T_A },
    { "SOA", T_SOA },
    { "NS", T_NS },
    { "TXT", T_TXT },
    { "ANY", T_ANY },
    { NULL, -1 }
};

static struct dns_mapping dns_classes[] = {
    { "IN", C_IN },
    { "CH", C_CHAOS },
    { "HS", C_HS },
    { "NONE", C_NONE },
    { "ANY", C_ANY },
    { NULL, -1 }
};

static size_t
dns_pack_labels(char *name,
                unsigned char *buf,
                size_t bufsize) {
    char *cp;
    size_t tlen, plen;

    plen = 0;
    while (*name) {
        cp = strchr(name, '.');
        tlen = cp ? cp-name : strlen(name);
        if (tlen > 255)
            return -1;

        if (plen+1+tlen > bufsize)
            return -1;

        buf[plen++] = tlen;
        memcpy(buf+plen, name, tlen);
        plen += tlen;

        name += tlen + (cp ? 1 : 0);
    }

    if (plen+1 > bufsize)
        return -1;
    buf[plen++] = 0;

    return plen;
}


static int
dns_get_uint16(void *buf,
	       size_t off) {
    unsigned char *bufp = (unsigned char *) buf;
    uint16_t rv;

    rv = * (uint16_t *) (bufp+off);
    return rv;
}

static int
dns_get_uint32(void *buf,
	       size_t off) {
    unsigned char *bufp = (unsigned char *) buf;
    uint32_t rv;

    rv = * (uint32_t *) (bufp+off);
    return rv;
}


static size_t
dns_unpack_labels(unsigned char *buf,
		  size_t pos,
		  char *label,
		  size_t size) {
    unsigned char *bufp;
    size_t len;


    bufp = buf+pos;
    while ((len = *bufp++) > 0) {
        if (len >= 64) {
            len &= 63;
            len <<= 8;
            len += *bufp++;
            dns_unpack_labels(buf, len, label, size);
            return bufp-buf;
        } else {
            while (len-- > 0) {
                if (size <= 0)
                    return -1;

                *label++ = *bufp++;
                --size;
            }
        }

        if (size <= 0)
            return -1;

        *label++ = '.';
        --size;
    }

    if (size <= 0)
        return -1;

    *label = '\0';

    return bufp-buf;
}



int
dns_udp_send_request(struct target *tp,
                     unsigned int *seq) {
    struct dns_request req;
    uint16_t xs = (*seq & 0xFFFF);
    size_t len = 0;


    memset(&req, 0, sizeof(req));
    req.h.id = htons(xs&0xFFFF);
    req.h.opcode = 0; /* 0 = Query, 1 = Inverse Query, 2 = Server status */

    if (f_payload) {
        unsigned char *bufp;
        char *cp, *ep;
        int type = T_A, class = C_IN;
        int i;

        for (cp = f_payload; cp; cp = ep) {
            ep = strchr(cp, ' ');
            if (ep)
                *ep = '\0';

            if (cp == f_payload) {
                len = dns_pack_labels(cp, req.b, sizeof(req.b));
                if (len < 0) {
                    fprintf(stderr, "%s: Error: %s: Invalid DNS name\n",
                            argv0, cp);
                    exit(1);
                }
            } else {
                for (i = 0; dns_types[i].s && strcasecmp(dns_types[i].s, cp); i++)
                    ;
                if (dns_types[i].s)
                    type = dns_types[i].v;
                else {
                    for (i = 0; dns_classes[i].s && strcasecmp(dns_classes[i].s, cp); i++)
                        ;
                    if (dns_classes[i].s)
                        class = dns_classes[i].v;
                    else {
                        fprintf(stderr, "%s: Error: %s: Invalid DNS type/class\n", argv0, cp);
                        exit(1);
                    }
                }
            }
            if (ep) {
                *ep = ' ';
                while (*ep && isspace(*ep))
                    ++ep;
            }
        }

        bufp = (unsigned char *) &req.b;
        bufp[len++] = 0;
        bufp[len++] = type;
        bufp[len++] = 0;
        bufp[len++] = class;

        req.h.qdcount = htons(1);

    } else
        len = 0;

    return send(tp->fd, (void *) &req, sizeof(req.h)+len, 0);
}

int
dns_tcp_send_request(struct target *tp,
                     unsigned int *seq) {
    struct dns_request req;
    uint16_t reqsize;
    uint16_t xs = (*seq & 0xFFFF);
    size_t len;
    struct msghdr msg;
    struct iovec iov[2];

    memset(&req, 0, sizeof(req));
    req.h.id = htons(xs&0xFFFF);
    req.h.opcode = 0; /* 0 = Query, 1 = Inverse Query, 2 = Server status */

    if (f_payload) {
        unsigned char *bufp;

        len = dns_pack_labels(f_payload, req.b, sizeof(req.b));
        if (len < 0) {
            fprintf(stderr, "%s: Error: %s: Invalid DNS name\n",
                    argv0, f_payload);
            exit(1);
        }

        bufp = (unsigned char *) &req.b;
        bufp[len++] = 0;
        bufp[len++] = 1; /* QTYPE = A */
        bufp[len++] = 0;
        bufp[len++] = 1; /* QCLASS = IN */

        req.h.qdcount = htons(1);

    } else
        len = 0;

    reqsize = htons(sizeof(req.h)+len);

    iov[0].iov_base = &reqsize;
    iov[0].iov_len = sizeof(reqsize);
    iov[1].iov_base = &req;
    iov[1].iov_len = reqsize;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov[0];
    msg.msg_iovlen = 2;

    return sendmsg(tp->fd, (void *) &msg, 0);
}


int
dns_udp_validate_reply(struct target *tp,
                       unsigned int seq,
                       struct timespec *t,
                       void *buf,
                       size_t buflen) {
    struct dns_reply *rep = (struct dns_reply *) buf;
    unsigned int rseq, anc, qdc;
    size_t pos;


    if (buflen < sizeof(*rep)) {
        return -1; /* Too small packet */
    }

    rseq = ntohs(rep->h.id);
    if (rseq != (seq&0xFFFF)) {
        return -2; /* Invalid sequence number */
    }

    if (rep->h.tc) {
        fprintf(stderr, "Truncated\n");
    }

    if (rep->h.rcode)
        return rep->h.rcode;

    qdc = ntohs(rep->h.qdcount);
    if (qdc != (f_payload ? 1 : 0)) {
        return -3; /* Invalid question count */
    }

    anc = ntohs(rep->h.ancount);
    if ((anc != 0) != (f_payload ? 1 : 0)) {
        return -4; /* Invalid answer count */
    }

    pos = sizeof(rep->h);
    while (qdc-- > 0) {
        char label[256];

        pos = dns_unpack_labels((unsigned char *) rep, pos, label, sizeof(label));
        if (f_verbose > 1)
            printf("%s\tType=%d", label, htons(dns_get_uint16(rep, pos)));
        pos += 2;
        if (f_verbose > 1)
            printf("\tClass=%d", htons(dns_get_uint16(rep, pos)));
        pos += 2;
        if (f_verbose > 1)
            putchar('\n');
    }

    while (anc-- > 0) {
        size_t rdlen;
        struct in_addr in;
        char label[256];

        pos = dns_unpack_labels((unsigned char *) rep, pos, label, sizeof(label));
        if (f_verbose)
            printf("%s\tType=%d", label, htons(dns_get_uint16(rep, pos)));
        pos += 2;
        if (f_verbose)
            printf("\tClass=%d", htons(dns_get_uint16(rep, pos)));
        pos += 2;
        if (f_verbose)
            printf("\tTTL=%d", htonl(dns_get_uint32(rep, pos)));
        pos += 4;
        rdlen = htons(dns_get_uint16(rep, pos));
        pos += 2;

        if (f_verbose) {
            if (rdlen == 4) {
                char buf[256];
                in.s_addr = dns_get_uint32(rep, pos);
                inet_ntop(AF_INET, &in, buf, sizeof(buf));
                printf("\t%s", buf);
            } else {
                printf("\t%s", "???");
            }
        }

        pos += rdlen;
        if (f_verbose)
            putchar('\n');
    }

    return 0;
}


int
dns_tcp_validate_reply(struct target *tp,
                       unsigned int seq,
                       struct timespec *t,
                       void *buf,
                       size_t buflen) {
    struct dns_reply *rep;
    unsigned int rseq, anc, qdc;
    size_t pos;
    uint16_t replen;

    if (buflen < sizeof(replen)) {
        return -1; /* Too small packet */
    }

    replen = ntohs( * (uint16_t *) buf );
    /* XXX: FIXME: Need to do a blocking read of the TCP Data */
    if (replen < sizeof(*rep) || replen >= buflen+2) {
        return -1; /* Too small packet */
    }

    rep = (struct dns_reply *) ( ((unsigned char *) buf)+2 );
    rseq = ntohs(rep->h.id);
    if (rseq != (seq&0xFFFF)) {
        return -2; /* Invalid sequence number */
    }

    if (rep->h.rcode)
        return rep->h.rcode;

    qdc = ntohs(rep->h.qdcount);
    if (qdc != (f_payload ? 1 : 0)) {
        return -3; /* Invalid question count */
    }

    anc = ntohs(rep->h.ancount);
    if ((anc != 0) != (f_payload ? 1 : 0)) {
        return -4; /* Invalid answer count */
    }

    pos = sizeof(rep->h);
    while (qdc-- > 0) {
        char label[256];

        pos = dns_unpack_labels((unsigned char *) rep, pos, label, sizeof(label));
        if (f_verbose > 1)
            printf("%s\tType=%d", label, htons(dns_get_uint16(rep, pos)));
        pos += 2;
        if (f_verbose > 1)
            printf("\tClass=%d", htons(dns_get_uint16(rep, pos)));
        pos += 2;
        if (f_verbose > 1)
            putchar('\n');
    }

    while (anc-- > 0) {
        size_t rdlen;
        struct in_addr in;
        char label[256];

        pos = dns_unpack_labels((unsigned char *) rep, pos, label, sizeof(label));
        if (f_verbose)
            printf("%s\tType=%d", label, htons(dns_get_uint16(rep, pos)));
        pos += 2;
        if (f_verbose)
            printf("\tClass=%d", htons(dns_get_uint16(rep, pos)));
        pos += 2;
        if (f_verbose)
            printf("\tTTL=%d", htonl(dns_get_uint32(rep, pos)));
        pos += 4;
        rdlen = htons(dns_get_uint16(rep, pos));
        pos += 2;

        if (f_verbose) {
            if (rdlen == 4) {
                char buf[256];
                in.s_addr = dns_get_uint32(rep, pos);
                inet_ntop(AF_INET, &in, buf, sizeof(buf));
                printf("\t%s", buf);
            } else {
                printf("\t%s", "???");
            }
        }

        pos += rdlen;
        if (f_verbose)
            putchar('\n');
    }

    return 0;
}
