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

#include "p4ping.h"
#include "snmp.h"


static int
build_v1_getrequest_descr(uint8_t *buf,
                               size_t bufsize,
                               char *community,
                               uint8_t reqid) {
    size_t i = 0;
    size_t clen = strlen(community);

    if (clen + 0x20 > bufsize)
        return -1;

    /* SEQUENCE */
    buf[i++] = 0x30;
    buf[i++] = 0x20 + clen;

    /* VERSION */
    buf[i++] = 0x02;
    buf[i++] = 0x01;
    buf[i++] = 0x00;

    /* COMMUNITY */
    buf[i++] = 0x04;
    buf[i++] = clen;
    while (clen-- > 0)
        buf[i++] = *community++;

    /* GET-REQUEST */
    buf[i++] = 0xA0;
    buf[i++] = 0x19;

    /* Request-ID */
    buf[i++] = 0x02;
    buf[i++] = 0x01;
    buf[i++] = reqid;

    /* Error-Status */
    buf[i++] = 0x02;
    buf[i++] = 0x01;
    buf[i++] = 0x00;

    /* Error-Index */
    buf[i++] = 0x02;
    buf[i++] = 0x01;
    buf[i++] = 0x00;

    /* VarBind-List */
    buf[i++] = 0x30;
    buf[i++] = 0x0E;

    /* VarBind */
    buf[i++] = 0x30;
    buf[i++] = 0x0C;

    /* sysDescr.0 */
    buf[i++] = 0x06;
    buf[i++] = 0x08;
    buf[i++] = 0x2B;
    buf[i++] = 0x06;
    buf[i++] = 0x01;
    buf[i++] = 0x02;
    buf[i++] = 0x01;
    buf[i++] = 0x01;
    buf[i++] = 0x01;
    buf[i++] = 0x00;

    /* NULL */
    buf[i++] = 0x05;
    buf[i++] = 0x00;

    return i;
}


int
snmp_send_request(struct target *tp,
                  unsigned int *seq) {
    uint8_t buf[512];
    ssize_t buflen;

    buflen = build_v1_getrequest_descr(buf, sizeof(buf), (f_payload ? f_payload : "public"), (uint8_t) *seq);
    if (buflen < 0)
        return -1;

    return sendto(tp->fd, (void *) buf, buflen, 0, tp->ai->ai_addr, tp->ai->ai_addrlen);

}


int
snmp_validate_reply(struct target *tp,
                    unsigned int seq,
                    struct timespec *t,
                    void *rbuf,
                    size_t rbuflen) {
    uint8_t *buf = (uint8_t *) rbuf;
    size_t i = 0;
    uint8_t sysdescr[512];


    if (rbuflen < 20)
        return -1;

    /* Outer SEQUENCE */
    if (buf[i++] != 0x30)
        return -2;

    /* Validate message length */
    if (buf[i++]+2 > rbuflen)
        return -3;

    // version INTEGER
    if (buf[i++] != 0x02)
        return -4;
    if (buf[i++] != 0x01)
        return -5;
    if (buf[i++] != 0x00)
        return -6;  // SNMPv1

    // community OCTET STRING
    if (buf[i++] != 0x04)
        return -7;
    uint8_t comm_len = buf[i++];
    i += comm_len;  // skip community

    // PDU: GetResponse-PDU = A2
    if (buf[i++] != 0xA2)
        return -8;
#if 1
    i++;
    #else
    uint8_t pdu_len = buf[i++];
    printf("pdu_len = %d\n", pdu_len);
#endif

    // request-id INTEGER
    if (buf[i++] != 0x02)
        return -9;
    if (buf[i++] != 0x01)
        return -10;
    /* Validate the Sequence ID */
    if (seq != buf[i++])
        return -11;

    // error-status INTEGER
    if (buf[i++] != 0x02)
        return -12;
    if (buf[i++] != 0x01)
        return -13;
    uint8_t err_status = buf[i++];

    // error-index INTEGER
    if (buf[i++] != 0x02)
        return -14;
    if (buf[i++] != 0x01)
        return -15;
    uint8_t err_index = buf[i++];

    if (err_status != 0 || err_index != 0)
        return -16;  // not a successful response

    // varbind-list SEQUENCE
    if (buf[i++] != 0x30)
        return -17;
#if 1
    i++;
#else
    uint8_t vbl_len = buf[i++];
    printf("vbl_len = %d\n", vbl_len);
#endif


    // varbind SEQUENCE
    if (buf[i++] != 0x30)
        return -18;
#if 1
    i++;
#else
    uint8_t vb_len = buf[i++];
    printf("vb_len = %d\n", vb_len);
#endif

    // OID
    if (buf[i++] != 0x06)
        return -19;

    uint8_t oid_len = buf[i++];
    if (oid_len != 8)
        return -20;

    // sysDescr.0 must be: 2B 06 01 02 01 01 01 00
    if (memcmp(&buf[i], "\x2B\x06\x01\x02\x01\x01\x01\x00", 8) != 0)
        return -21;
    i += oid_len;

    // Value: OCTET STRING
    if (buf[i++] != 0x04)
        return -22;

    uint8_t val_len = buf[i++];
    if (val_len >= sizeof(sysdescr))
        return -1;

    memcpy(sysdescr, &buf[i], val_len);
    sysdescr[val_len] = '\0';

    if (f_verbose)
        fprintf(stderr, "SNMPv1: sysDescr=%s\n", sysdescr);

    return 0;
}
