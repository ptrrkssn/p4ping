/*
 * krb.c
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
#include <stdint.h>
#include <stddef.h>

#include "krb.h"

#if 0
/* Write TAG + LENGTH (short form only) */
static int put_tag_len(uint8_t *buf, size_t max, uint8_t tag, size_t len)
{
    if (max < 2 || len > 127) return -1;
    buf[0] = tag;
    buf[1] = (uint8_t)len;
    return 2;
}
#endif

static int put_integer(uint8_t *buf, size_t max, uint32_t val)
{
    uint8_t tmp[5];
    int len = 0;

    /* Encode big-endian without leading zeros */
    if (val <= 0x7F) {
        tmp[len++] = (uint8_t)val;
    } else if (val <= 0xFF) {
        tmp[len++] = (uint8_t)val;
    } else if (val <= 0xFFFF) {
        tmp[len++] = (uint8_t)(val >> 8);
        tmp[len++] = (uint8_t)(val);
    } else if (val <= 0xFFFFFF) {
        tmp[len++] = (uint8_t)(val >> 16);
        tmp[len++] = (uint8_t)(val >> 8);
        tmp[len++] = (uint8_t)(val);
    } else {
        tmp[len++] = (uint8_t)(val >> 24);
        tmp[len++] = (uint8_t)(val >> 16);
        tmp[len++] = (uint8_t)(val >> 8);
        tmp[len++] = (uint8_t)(val);
    }

    /* If MSB is 1, prepend 0x00 to keep integer positive */
    if (tmp[0] & 0x80) {
        if (max < len + 3) return -1;
        buf[0] = 0x02;          /* INTEGER */
        buf[1] = (uint8_t)(len + 1);
        buf[2] = 0x00;          /* sign padding */
        memcpy(buf + 3, tmp, len);
        return len + 3;
    }

    /* Normal case */
    if (max < len + 2) return -1;
    buf[0] = 0x02;
    buf[1] = (uint8_t)len;
    memcpy(buf + 2, tmp, len);
    return len + 2;
}

#if 0
/* INTEGER */
static int put_integer(uint8_t *buf, size_t max, int val)
{
    if (max < 3) return -1;
    buf[0] = 0x02;   /* INTEGER */
    buf[1] = 0x01;   /* length */
    buf[2] = (uint8_t)val;
    return 3;
}
#endif

/* GeneralString */
static int put_generalstring(uint8_t *buf, size_t max, const char *s)
{
    size_t len = strlen(s);
    if (max < len + 2 || len > 127) return -1;
    buf[0] = 0x1B;
    buf[1] = (uint8_t)len;
    memcpy(buf + 2, s, len);
    return (int)(len + 2);
}

static int wrap_sequence(uint8_t *buf, size_t max,
                         const uint8_t *inner, size_t inner_len)
{
    if (inner_len < 128) {
        /* Short form: 30 <len> <inner> */
        if (max < inner_len + 2) return -1;
        buf[0] = 0x30;
        buf[1] = (uint8_t)inner_len;
        memcpy(buf + 2, inner, inner_len);
        return (int)(inner_len + 2);
    }

    if (inner_len < 256) {
        /* Long form: 30 81 <len> <inner> */
        if (max < inner_len + 3) return -1;
        buf[0] = 0x30;
        buf[1] = 0x81;
        buf[2] = (uint8_t)inner_len;
        memcpy(buf + 3, inner, inner_len);
        return (int)(inner_len + 3);
    }

    /* Larger sequences: 30 82 <len_hi> <len_lo> <inner> */
    if (inner_len < 65536) {
        if (max < inner_len + 4) return -1;
        buf[0] = 0x30;
        buf[1] = 0x82;
        buf[2] = (uint8_t)(inner_len >> 8);
        buf[3] = (uint8_t)(inner_len & 0xFF);
        memcpy(buf + 4, inner, inner_len);
        return (int)(inner_len + 4);
    }

    /* Too large for DER SEQUENCE in this context */
    return -1;
}

#if 0
/* SEQUENCE wrapper */
static int
wrap_sequence(uint8_t *buf,
	      size_t max,
	      const uint8_t *inner,
	      size_t inner_len)
{
    if (max < inner_len + 2 || inner_len > 127) {
      printf("max = %d, inner_len = %d\n", max, inner_len);
      abort();
      return -1;
    }
    
    buf[0] = 0x30;
    buf[1] = (uint8_t)inner_len;
    memcpy(buf + 2, inner, inner_len);
    
    return (int)(inner_len + 2);
}
#endif

static int put_principalname(uint8_t *buf, size_t max, const char *name)
{
    uint8_t inner[256];
    int off = 0;

    /* name-type [0] INTEGER 1 */
    inner[off++] = 0xA0;
    inner[off++] = 0x03;
    off += put_integer(inner + off, sizeof(inner) - off, 1);

    /* name-string [1] SEQUENCE OF GeneralString */
    uint8_t gs[256];
    int gs_len = put_generalstring(gs + 2, sizeof(gs) - 2, name);
    gs[0] = 0x30;
    gs[1] = (uint8_t)gs_len;
    gs_len += 2;

    inner[off++] = 0xA1;
    inner[off++] = (uint8_t)gs_len;
    memcpy(inner + off, gs, gs_len);
    off += gs_len;

    return wrap_sequence(buf, max, inner, off);
}

static int put_servicename(uint8_t *buf, size_t max, const char *name, const char *realm)
{
    uint8_t inner[256];
    int off = 0;

    /* name-type [0] INTEGER 1 */
    inner[off++] = 0xA0;
    inner[off++] = 0x03;
    off += put_integer(inner + off, sizeof(inner) - off, 2);

    /* name-string [1] SEQUENCE OF GeneralString */
    uint8_t gs[256];
    int gs_len = put_generalstring(gs + 2, sizeof(gs) - 2, name);
    printf("gs_len = %d, off=%d\n", gs_len, off);
    if (gs_len < 0)
      abort();
    gs[0] = 0x30;
    gs[1] = (uint8_t)gs_len;
    gs_len += 2;

    inner[off++] = 0xA1;
    inner[off++] = (uint8_t)gs_len;
    memcpy(inner + off, gs, gs_len);
    off += gs_len;


    /* name-string [2] SEQUENCE OF GeneralString */
    uint8_t rs[256];
    int rs_len = put_generalstring(rs + 2, sizeof(rs) - 2, realm);
    printf("rs_len = %d off=%d\n", rs_len, off);
    if (rs_len < 0)
      abort();
    rs[0] = 0x30;
    rs[1] = (uint8_t)rs_len;
    rs_len += 2;
    
    inner[off++] = 0xA2;
    inner[off++] = (uint8_t)rs_len;
    memcpy(inner + off, rs, rs_len);
    off += rs_len;

    
    return wrap_sequence(buf, max, inner, off);
}


static int put_empty_padata(uint8_t *buf, size_t max)
{
    uint8_t empty_seq[2] = {0x30, 0x00}; /* SEQUENCE {} */
    return wrap_sequence(buf, max, empty_seq, 2);
}



/*
 * Build KerberosTime string: "YYYYMMDDhhmmssZ"
 */
static void build_kerberos_time(char *out,
				size_t outsize)
{
    time_t t = time(NULL);
    struct tm g;
    gmtime_r(&t, &g);

    snprintf(out, outsize, "%04d%02d%02d%02d%02d%02dZ",
             g.tm_year + 1900,
             g.tm_mon + 1,
             g.tm_mday,
             g.tm_hour,
             g.tm_min,
             g.tm_sec);
}

static int put_generalized_time(uint8_t *buf, size_t max, const char *timestr)
{
    size_t len = strlen(timestr);
    if (len > 127 || max < len + 2)
        return -1;

    buf[0] = 0x18;          /* GeneralizedTime tag */
    buf[1] = (uint8_t)len;  /* short-form length */
    memcpy(buf + 2, timestr, len);

    return (int)(len + 2);
}

static int put_kdc_req_body(uint8_t *buf, size_t max,
                            const char *realm,
                            const char *principal,
                            uint32_t nonce)
{
    uint8_t inner[1024];
    int off = 0;
    uint8_t tag = 0xA0;
    
    /* kdc-options [0] BIT STRING (all zero, 32 bits) */
    inner[off++] = tag++;
    inner[off++] = 0x05;
    inner[off++] = 0x03; /* BIT STRING */
    inner[off++] = 0x03; /* length */
    inner[off++] = 0x00; /* unused bits */
    inner[off++] = 0x00;
    inner[off++] = 0x00;

    /* cname [1] */
    inner[off++] = tag++;
    {
        uint8_t tmp[256];
        int len = put_principalname(tmp, sizeof(tmp), principal);
        inner[off++] = (uint8_t)len;
        memcpy(inner + off, tmp, len);
        off += len;
    }

    /* realm [2] */
    inner[off++] = tag++;
    {
        uint8_t tmp[256];
        int len = put_generalstring(tmp, sizeof(tmp), realm);
        inner[off++] = (uint8_t)len;
        memcpy(inner + off, tmp, len);
        off += len;
    }

    /* sname [3] = krbtgt */
    inner[off++] = tag++;
    {
      uint8_t tmp[512];
      int len = put_servicename(tmp, sizeof(tmp), "krbtgt", realm);
      inner[off++] = (uint8_t)len;
      memcpy(inner + off, tmp, len);
      off += len;
    }
    
    /* till [5] KerberosTime */
    ++tag;
    inner[off++] = tag++;
    {
      char kt[16];
      build_kerberos_time(kt, sizeof(kt));
      
      uint8_t tmp[32];
      int len = put_generalized_time(tmp, sizeof(tmp), kt);
      inner[off++] = (uint8_t)len;
      memcpy(inner + off, tmp, len);
      off += len;
    }
    
    ++tag;
    /* nonce [5] */
    inner[off++] = tag++;
    {
        uint8_t tmp[16];
        int len = put_integer(tmp, sizeof(tmp), nonce);
        inner[off++] = (uint8_t)len;
        memcpy(inner + off, tmp, len);
        off += len;
    }

    /* etype [6] = SEQUENCE { INTEGER 18 } */
    inner[off++] = tag++;
    {
        uint8_t seq[16];
        int len = put_integer(seq + 2, sizeof(seq) - 2, 18);
        seq[0] = 0x30;
        seq[1] = (uint8_t)len;
        len += 2;

        inner[off++] = (uint8_t)len;
        memcpy(inner + off, seq, len);
        off += len;
    }

    return wrap_sequence(buf, max, inner, off);
}


size_t build_krb_as_req_empty_padata(uint8_t *buf, size_t max,
                                     const char *realm,
                                     const char *principal,
                                     uint32_t nonce)
{
    uint8_t inner[2048];
    int off = 0;
    uint8_t tag = 0xA1;
    
    /* pvno [0] = 5 */
    inner[off++] = tag++;
    inner[off++] = 0x03;
    off += put_integer(inner + off, sizeof(inner) - off, 5);

    /* msg-type [1] = 10 */
    inner[off++] = tag++;
    inner[off++] = 0x03;
    off += put_integer(inner + off, sizeof(inner) - off, 10);

    /* padata [2] = empty */
    inner[off++] = tag++;
    {
        uint8_t tmp[16];
        int len = put_empty_padata(tmp, sizeof(tmp));
        inner[off++] = (uint8_t)len;
        memcpy(inner + off, tmp, len);
        off += len;
    }

    /* req-body [3] */
    inner[off++] = tag++;
    {
        uint8_t tmp[1024];
        int len = put_kdc_req_body(tmp, sizeof(tmp),
                                   realm, principal, nonce);
        inner[off++] = (uint8_t)len;
        memcpy(inner + off, tmp, len);
        off += len;
    }

    /* Wrap in SEQUENCE */
    uint8_t seq[4096];
    int s_len = wrap_sequence(seq, sizeof(seq), inner, off);

    /* Wrap in [APPLICATION 10] */
    if (max < (size_t)(s_len + 2)) return 0;
    buf[0] = 0x6A;          /* [APPLICATION 10] */
    buf[1] = (uint8_t)s_len;
    memcpy(buf + 2, seq, s_len);

    return s_len + 2;
}



int
krb_send_request(struct target *tp,
                 unsigned int *seq) {
    uint8_t buf[2048];
    ssize_t buflen;
    uint32_t nonce = 0x12345678;
    
#if 1
    buflen = build_krb_as_req_empty_padata(buf, sizeof(buf), "AD.LIU.SE", "peter86", nonce);
#else
    buflen = build_minimal_krb_as_req(buf, sizeof(buf));
#endif
    if (buflen < 0)
        return -1;

    return sendto(tp->fd, (void *) buf, buflen, 0, tp->ai->ai_addr, tp->ai->ai_addrlen);
}


int
krb_validate_reply(struct target *tp,
                   unsigned int seq,
                   struct timespec *t,
                   void *rbuf,
                   size_t rbuflen) {
    return -1;
}
