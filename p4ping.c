/*
 * p4ping.c
 *
 * Copyright (c) 2023-2025 Peter Eriksson <pen@lysator.liu.se>
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
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <stdatomic.h>

#ifdef HAVE_LINUX_ICMP_H
#include <linux/icmp.h>
#else
#include <netinet/ip_icmp.h>
#endif
#include <netinet/icmp6.h>


char *version = PACKAGE_VERSION;
char *argv0 = "p4ping";

char *f_protocol = "icmp";
char *f_service = NULL;

int f_family = AF_UNSPEC;
int f_timeout = 1;
int f_interval = 1;
int f_tcp = 0;
int f_cont = 3;
int f_verbose = 0;
int f_summary = 0;
int f_ignore = 0;
int f_script = 0;
int f_numeric = 0;
int f_silent = 0;
int f_ttl = 0;
int f_display = 0;
int f_warning = 1;
int f_critical = 0;
int f_syslog = -1;

uint16_t f_ident = 0;
char *f_payload = NULL;
char *d_payload = "[p4ping]";

atomic_char got_sigint = 0;


double
diff_timespec(struct timespec *t0,
              struct timespec *t1) {
  return (t0->tv_sec-t1->tv_sec) + (t0->tv_nsec-t1->tv_nsec)/1000000000.0;
}

int
print_timespec(FILE *fp,
	       struct timespec *ts) {
  char buf[64];
  int rc;
  struct tm t;
  int len = sizeof(buf);


  tzset();
  if (localtime_r(&(ts->tv_sec), &t) == NULL)
    return -1;

  rc = strftime(buf, len, "%F %T", &t);
  if (rc <= 0)
    return -1;

  len -= rc;

  rc = snprintf(buf+strlen(buf), len,
                (f_verbose ? ".%09ld" : ".%03ld"),
                f_verbose ? ts->tv_nsec : ts->tv_nsec/1000000);
  if (rc >= len)
    return -1;

  return fputs(buf, fp);
}


void
sigint_handler(int sig) {
  got_sigint = 1;
}

void
sigalrm_handler(int sig) {
}


int
display_buffer(FILE *outfp,
	       void *buf,
	       size_t buflen) {
  unsigned char *bufp = (unsigned char *) buf;
  unsigned char *endp = bufp+buflen;
  int i;

  while (bufp < endp) {
    putc(' ', outfp);
    putc(' ', outfp);
    putc(' ', outfp);
    putc(' ', outfp);
    for (i = 0; i < 16 && bufp+i < endp; i++) {
      if (i > 0)
	putc(' ', outfp);
      if (i == 8)
	putc(' ', outfp);
      fprintf(outfp, "%02x", bufp[i]);
    }
    for (; i < 16; i++) {
      if (i == 8)
	putc(' ', outfp);
      fputs("   ", outfp);
    }

    putc(' ', outfp);
    putc(' ', outfp);
    putc(' ', outfp);
    putc(' ', outfp);
    for (i = 0; i < 16 && bufp < endp; i++) {
      if (i > 0)
	putc(' ', outfp);
      if (i == 8)
	putc(' ', outfp);
      putc(isprint(*bufp) ? *bufp : '?', outfp);
      ++bufp;
    }

    putc('\n', outfp);
  }

  return 0;
}



typedef struct target {
  int fd;
  char *addr;
  char *name;
  struct addrinfo *ai;
  struct timespec t0;
  struct timespec t1;
  struct {
    unsigned long sent;
    unsigned long missed;
  } packets;
  struct {
    double min;
    double max;
    double sum;
  } rtt;
  struct target *next;
} TARGET;

TARGET *tlist = NULL;




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


unsigned int
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
send_icmp_echo_request(struct target *tp,
                       unsigned int *seq) {
  struct icmp_echo ep;
  size_t plen, eplen;
  uint16_t xs = (*seq & 0xFFFF);
  char *payload = f_payload ? f_payload : d_payload;


  *seq = xs;
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
validate_icmp_echo_reply(struct target *tp,
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

int
send_ntp_request(struct target *tp,
                 unsigned int *seq) {
  unsigned char tbuf[48];

  memset(tbuf, 0, sizeof(tbuf));
  tbuf[0] = 0x1B;

  return sendto(tp->fd, tbuf, sizeof(tbuf), 0, tp->ai->ai_addr, tp->ai->ai_addrlen);
}

int
send_udp_echo_request(struct target *tp,
                  unsigned int *seq) {
    unsigned int tbuf = htonl(*seq);

  return sendto(tp->fd, &tbuf, sizeof(tbuf), 0, tp->ai->ai_addr, tp->ai->ai_addrlen);
}

int
validate_udp_echo_reply(struct target *tp,
                        unsigned int seq,
                        struct timespec *t,
                        void *buf,
                        size_t buflen) {
    unsigned int rseq;

    if (buflen != sizeof(rseq))
        return -1;

    rseq = ntohl(*(unsigned int *)buf);
    if (rseq != seq)
        return -6;

    return 0;
}

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


size_t
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


int
dns_get_uint16(void *buf,
	       size_t off) {
  unsigned char *bufp = (unsigned char *) buf;
  uint16_t rv;

  rv = * (uint16_t *) (bufp+off);
  return rv;
}

int
dns_get_uint32(void *buf,
	       size_t off) {
  unsigned char *bufp = (unsigned char *) buf;
  uint32_t rv;

  rv = * (uint32_t *) (bufp+off);
  return rv;
}


size_t
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
send_dns_request(struct target *tp,
                 unsigned int *seq) {
  struct dns_request req;
  uint16_t xs = (*seq & 0xFFFF);
  size_t len;


  *seq = xs;
  memset(&req, 0, sizeof(req));
  req.h.id = htons((xs+getpid()*10)&0xFFFF);
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
    bufp[len++] = 1;
    bufp[len++] = 0;
    bufp[len++] = 1;

    req.h.qdcount = htons(1);

  } else
      len = 0;

  return sendto(tp->fd, (void *) &req, sizeof(req.h)+len, 0, tp->ai->ai_addr, tp->ai->ai_addrlen);
}


int
validate_dns_reply(struct target *tp,
                   unsigned int seq,
                   struct timespec *t,
                   void *buf,
                   size_t buflen) {
  struct dns_reply *rep = (struct dns_reply *) buf;
  unsigned int rseq, anc, qdc;
  size_t pos;


  if (buflen < sizeof(*rep))
    return -1;

  rseq = ntohs(rep->h.id);
  if (rseq != ((seq+getpid()*10) & 0xFFFF))
    return -1; /* Invalid sequence number */

  qdc = ntohs(rep->h.qdcount);
  if (qdc != (f_payload ? 1 : 0)) {
    return -2; /* Invalid question count */
  }

  anc = ntohs(rep->h.ancount);
  if ((anc != 0) != (f_payload ? 1 : 0)) {
    return 3; /* Invalid answer count */
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
send_udp_request(struct target *tp,
                 unsigned int *seq) {
  unsigned char tbuf[512];

  memset(tbuf, 0, sizeof(tbuf));
  return sendto(tp->fd, tbuf, sizeof(tbuf), 0, tp->ai->ai_addr, tp->ai->ai_addrlen);
}


struct protocol {
  char *name;
  int ai_socktype;
  int ai_protocol;
  char *ai_service;
  int (*setup)(struct addrinfo *aip);
  int (*request)(struct target *tp, unsigned int *seq);
  int (*response)(struct target *tp, unsigned int seq, struct timespec *t0, void *buf, size_t buflen);
} protocols[] = {
  { "icmp",
    SOCK_RAW, IPPROTO_ICMP, NULL,
    NULL, send_icmp_echo_request, validate_icmp_echo_reply },
  { "ntp",
    SOCK_DGRAM, 0, "ntp",
    NULL, send_ntp_request, NULL },
  { "echo",
    SOCK_DGRAM, 0, "echo",
    NULL, send_udp_echo_request, validate_udp_echo_reply },
  { "dns",
    SOCK_DGRAM, 0, "domain",
    NULL, send_dns_request, validate_dns_reply },
  { "dns/tcp",
    SOCK_STREAM, 0, "domain",
    NULL, send_dns_request, validate_dns_reply },
  { "udp",
    SOCK_DGRAM, 0, "echo",
    NULL, send_udp_request, NULL },
  { NULL,
    -1, -1,
    NULL, NULL, NULL }
};


struct syslog_fac {
  char *name;
  int fac;
} logfacv[] = {
  { "auth", LOG_AUTH },
  { "authpriv", LOG_AUTHPRIV },
  { "cron", LOG_CRON },
  { "daemon", LOG_DAEMON },
  { "ftp", LOG_FTP },
  { "local0", LOG_LOCAL0 },
  { "local1", LOG_LOCAL1 },
  { "local2", LOG_LOCAL2 },
  { "local3", LOG_LOCAL3 },
  { "local4", LOG_LOCAL4 },
  { "local5", LOG_LOCAL5 },
  { "local6", LOG_LOCAL6 },
  { "local7", LOG_LOCAL7 },
  { "lpr", LOG_LPR },
  { "mail", LOG_MAIL },
  { "news", LOG_NEWS },
  { "user", LOG_USER },
  { "uucp", LOG_UUCP },
  { NULL, -1 }
};

int
str2fac(const char *str,
        int *fac) {
  int i;

  for (i = 0; logfacv[i].name && strcmp(logfacv[i].name, str) != 0; i++)
    ;

  if (fac)
    *fac = logfacv[i].fac;

  return logfacv[i].fac;
}


int
main(int argc,
     char *argv[]) {
  int rc, i, j, k, v, rlen;
  unsigned int seq;
  unsigned char rbuf[MAXBUFSIZE+1024];
  char hbuf[NI_MAXHOST];
  double td, rtt;
  struct timespec t0, t1;
  struct sigaction sa;
  struct addrinfo hints, *result, *rp;
  TARGET *tp;
  union {
    struct sockaddr_in from4;
    struct sockaddr_in6 from6;
  } frombuf;
  struct sockaddr *fromp;
  socklen_t flen;
  struct pollfd *pfdv;
  int pfdn;
  int addrlen = 0;
  int namelen = 0;
  struct protocol *pp;


  argv0 = argv[0];
  srandom(time(NULL)^getpid());
  f_ident = random();

  for (i = 1; i < argc && argv[i][0] == '-'; i++) {
    for (j = 1; argv[i][j]; j++) {
      switch (argv[i][j]) {
      case 'h':
        printf("Usage:\n  %s [<options>] <host> [..<host-N>]\n", argv[0]);
        puts("\nOptions:");
        puts("  -h            Display this information");
        puts("  -v            Be more verbose");
        puts("  -s            Be silent");
        puts("  -i            Ignore checksum errors");
        puts("  -1 / -2 / -3  One(two/three)-shot ping");
        puts("  -c            Continous ping");
        puts("  -f            Flood ping (no delay)");
        puts("  -n            No DNS lookup");
        puts("  -d            Display response packet");
        puts("  -4            Force IPv4");
        puts("  -6            Force IPv6");
        printf("  -P<protocol>  Type of protocol (");
        for (k = 0; protocols[k].name; k++) {
          if (k > 0)
            putchar('|');
          fputs(protocols[k].name, stdout);
        }
        puts(")");
        puts("  -I<time>      Interval between pings");
        puts("  -T<ttl>       Packet TTL");
        puts("  -W<missed>    Warning level of missed packets");
        puts("  -C<missed>    Critical level of missed packets");
        puts("  -S<service>   Force IP service (port) number");
        puts("  -L<facility>  Enable syslog");
        puts("  -D<data>      Payload data");
        exit(0);

      case '4':
        f_family = AF_INET;
        break;
      case '6':
        f_family = AF_INET6;
        break;
      case 'v':
        f_verbose++;
        break;
      case 'i':
        f_ignore++;
        break;
      case 's':
        f_silent++;
        break;
      case '1':
      case '2':
      case '3':
        f_cont = argv[i][j]-'0';
        break;
      case 'c':
        f_cont = -1;
      case 'f':
        f_interval = 0;
        break;
      case 'n':
        f_numeric++;
        break;
      case 'd':
        f_display++;
        break;
      case 'P':
        if (argv[i][j+1])
          f_protocol = argv[i]+j+1;
        else if (i+1 < argc && argv[i+1][0] != '-')
          f_protocol = argv[++i];
        else {
          fprintf(stderr, "%s: Error: -P: Missing required argument\n",
                  argv[0]);
          exit(1);
        }
        goto NextArg;

      case 'S':
        if (argv[i][j+1])
          f_service = argv[i]+j+1;
        else if (i+1 < argc && argv[i+1][0] != '-')
          f_service = argv[++i];
        else {
          fprintf(stderr, "%s: Error: -S: Missing required argument\n",
                  argv[0]);
          exit(1);
        }
        goto NextArg;

      case 'L':
        rc = -1;
        if (argv[i][j+1]) {
          if ((rc = str2fac(argv[i]+j+1, &f_syslog)) >= 0)
            goto NextArg;
        } else if (i+1 < argc && argv[i+1][0] != '-') {
          if ((rc = str2fac(argv[++j], &f_syslog)) >= 0)
            goto NextArg;
        }
        if (rc < 0) {
          fprintf(stderr, "%s: Error: -L: Missing or invalid syslog facility\n",
                  argv[0]);
          exit(1);
        }
        goto NextArg;

      case 'D':
        if (argv[i][j+1])
          f_payload = argv[i]+j+1;
        else if (i+1 < argc && argv[i+1][0] != '-')
          f_payload = argv[++i];
        else {
          fprintf(stderr, "%s: Error: -S: Missing required argument\n",
                  argv[0]);
          exit(1);
        }
        goto NextArg;

      case 'I':
        rc = 0;
        if (argv[i][j+1]) {
          if ((rc = sscanf(argv[i]+j+1, "%u", &f_interval)) == 1)
            goto NextArg;
        } else if (i+1 < argc && argv[i+1][0] != '-') {
          if ((rc = sscanf(argv[++i], "%u", &f_interval)) == 1)
            goto NextArg;
        }
        if (rc != 1) {
          fprintf(stderr, "%s: Error: -I: Missing or invalid required argument\n",
                  argv[0]);
          exit(1);
        }
        goto NextArg;

      case 'W':
        rc = 0;
        if (argv[i][j+1]) {
          if ((rc = sscanf(argv[i]+j+1, "%u", &f_warning)) == 1)
            goto NextArg;
        } else if (i+1 < argc && argv[i+1][0] != '-') {
          if ((rc = sscanf(argv[++i], "%u", &f_warning)) == 1)
            goto NextArg;
        }
        if (rc != 1) {
          fprintf(stderr, "%s: Error: -W: Missing or invalid required argument\n",
                  argv[0]);
          exit(1);
        }
        goto NextArg;

      case 'C':
        rc = 0;
        if (argv[i][j+1]) {
          if ((rc = sscanf(argv[i]+j+1, "%u", &f_critical)) == 1)
            goto NextArg;
        } else if (i+1 < argc && argv[i+1][0] != '-') {
          if ((rc = sscanf(argv[++i], "%u", &f_critical)) == 1)
            goto NextArg;
        }
        if (rc != 1) {
          fprintf(stderr, "%s: Error: -I: Missing or invalid required argument\n",
                  argv[0]);
          exit(1);
        }
        goto NextArg;

      case 'T':
        rc = 0;
        if (argv[i][j+1]) {
          if ((rc = sscanf(argv[i]+j+1, "%u", &f_ttl)) == 1)
            goto NextArg;
        } else if (i+1 < argc && argv[i+1][0] != '-') {
          if ((rc = sscanf(argv[++i], "%u", &f_ttl)) == 1)
            goto NextArg;
        }
        if (rc != 1) {
          fprintf(stderr, "%s: Error: -T: Missing or invalid required argument\n",
                  argv[0]);
          exit(1);
        }
        goto NextArg;

      case '\0':
      case '-':
        i++;
        goto EndArg;

      default:
        fprintf(stderr, "%s: Error: -%c: Invalid switch\n", argv[0], argv[i][j]);
        exit(1);
      }
    }
  NextArg:;
  }

  if (f_verbose)
    printf("[p4ping, version %s - Copyright (c) 2023-2025 Peter Eriksson <pen@lysator.liu.se>]\n", version);

 EndArg:
  if (i >= argc) {
    fprintf(stderr, "%s: Error: Missing required <hosts> arguments\n", argv[0]);
    exit(1);
  }

  if (f_syslog != -1)
    openlog("p4ping", 0, f_syslog);

  for (j = 0; protocols[j].name && strcmp(protocols[j].name, f_protocol) != 0; j++)
    ;
  if (!protocols[j].name) {
    fprintf(stderr, "%s: Error: %s: Invalid protocol\n",
            argv[0], f_protocol);
    exit(1);
  }
  pp = &protocols[j];

  pfdn = 0;

  /* For each target specified on the command line */
  for (; i < argc; i++) {
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = f_family;
    hints.ai_socktype = pp->ai_socktype;
    hints.ai_flags = AI_ADDRCONFIG;
    hints.ai_protocol = pp->ai_protocol;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    rc = getaddrinfo(argv[i], (f_service ? f_service : pp->ai_service), &hints, &result);
    if (rc != 0) {
      fprintf(stderr, "%s: Error: %s: getaddrinfo: %s\n",
              argv[0], argv[i], gai_strerror(rc));
      exit(1);
    }

    /* For each target IP address found */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
      int fd = -1;


      if (rp->ai_family == AF_INET6 && pp->ai_protocol == IPPROTO_ICMP)
        rp->ai_protocol = IPPROTO_ICMPV6;

      /* For ICMP & ICMPV6 we reuse previously allocated sockets */
      if (rp->ai_protocol == IPPROTO_ICMP ||
          rp->ai_protocol == IPPROTO_ICMPV6) {
        for (tp = tlist; tp; tp = tp->next) {
	  if (tp->ai->ai_protocol == rp->ai_protocol)
	    break;
	}
        if (tp) {
          fd = tp->fd;
	}
      }

      if (fd < 0) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
          fprintf(stderr, "%s: Error: %s: socket: %s\n",
                  argv[0], argv[i], strerror(errno));
          continue;
        }

#ifdef ICMP_FILTER
        if (rp->ai_protocol == IPPROTO_ICMP) {
          struct icmp_filter ifb;

          ifb.data = ICMP_ECHOREPLY;
          rc = setsockopt(fd, SOL_RAW, ICMP_FILTER, &ifb, sizeof(ifb));
          if (fd < 0) {
            fprintf(stderr, "%s: Notice: %s: setsockopt(ICMP_FILTER): %s [ignored]\n",
                    argv[0], argv[i], strerror(errno));
          }
        }
#endif
#ifdef ICMP6_FILTER
        if (rp->ai_protocol == IPPROTO_ICMPV6) {
          struct icmp6_filter ifb;

          ICMP6_FILTER_SETBLOCKALL(&ifb);
          ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &ifb);
          rc = setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &ifb, sizeof(ifb));
          if (fd < 0) {
            fprintf(stderr, "%s: Notice: %s: setsockopt(ICMP_FILTER): %s [ignored]\n",
                    argv[0], argv[i], strerror(errno));
          }
        }
#endif
#if 0
        if (rp->ai_protocol == IPPROTO_ICMPV6) {
          int offset = offsetof(struct icmp_echo_header, checksum);
          rc = setsockopt(fd, SOL_RAW, IPV6_CHECKSUM, &offset, sizeof(offset));
          if (rc < 0) {
            fprintf(stderr, "%s: Error: %s: setsockopt(SOL_RAW, IPV6_CHECKSUM): %s\n",
                    argv[0], argv[i], strerror(errno));
            exit(1);
          }
        }
#endif

        if (f_ttl) {
          rc = setsockopt(fd, IPPROTO_IP, IP_TTL, &f_ttl, sizeof(f_ttl));
          if (rc < 0) {
            fprintf(stderr, "%s: Error: %s: setsockopt(IPPROTO_IP, IP_TTL): %s\n",
                    argv[0], argv[i], strerror(errno));
            exit(1);
          }
        }
      }

      tp = malloc(sizeof(*tp));
      if (!tp) {
        fprintf(stderr, "%s: Error: %ld: malloc: %s\n",
                argv[0], sizeof(*tp), strerror(errno));
        exit(1);
      }
      memset(tp, 0, sizeof(*tp));

      tp->fd = fd;
      tp->ai = rp;

      rc = getnameinfo(rp->ai_addr, rp->ai_addrlen,
                       hbuf, sizeof(hbuf),
                       NULL, 0,
                       NI_NUMERICHOST);
      if (rc != 0) {
        fprintf(stderr, "%s: Error: %s: getnameinfo(NI_NUMERICHOST): %s\n",
                argv[0], argv[i], gai_strerror(rc));
        exit(1);
      }

      tp->addr = strdup(hbuf);
      v = strlen(tp->addr);
      if (v > addrlen)
        addrlen = v;

      if (!f_numeric) {
        rc = getnameinfo(rp->ai_addr, rp->ai_addrlen,
                         hbuf, sizeof(hbuf),
                         NULL, 0,
                         NI_NAMEREQD);
        if (rc == 0) {
          tp->name = strdup(hbuf);
        } else {
          fprintf(stderr, "%s: Notice: %s: getnameinfo(NI_NAMEREQD): %s\n",
                  argv[0], argv[i], gai_strerror(rc));
          tp->name = strdup(argv[i]);
        }
        v = strlen(tp->name);
        if (v > namelen)
          namelen = v;
      }

      tp->rtt.min = -1;
      tp->rtt.max = 0;
      tp->rtt.sum = 0;

      pfdn++;
      tp->next = tlist;
      tlist = tp;
    }
  }

  if (!pfdn) {
    fprintf(stderr, "%s: Error: No IP addresses to ping!\n",
            argv[0]);
    exit(1);
  }

  pfdv = calloc(pfdn, sizeof(struct pollfd));
  if (!pfdv) {
    fprintf(stderr, "%s: Error: calloc: %s\n", argv[0], strerror(errno));
    exit(1);
  }


    /* Setup response timeout */
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigint_handler;
  sigaction(SIGINT, &sa, NULL);

  seq = 0;
  
  do {
    int na;


    /* Setup response timeout */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigalrm_handler;
    sigaction(SIGALRM, &sa, NULL);
    alarm(f_timeout);

    clock_gettime(CLOCK_REALTIME, &t0);

    /* Transmit request packets to all targets */
    na = 0;
    for (tp = tlist; tp; tp = tp->next) {
      clock_gettime(CLOCK_REALTIME, &tp->t0);

      rc = pp->request(tp, &seq);
      if (rc < 0) {
        fprintf(stderr, "%s: Error: %s [%s]: send-request: %s\n",
                argv[0], tp->addr, tp->name, strerror(errno));
        exit(1);
      }

      tp->t1.tv_sec = 0;
      tp->t1.tv_nsec = 0;
      tp->packets.sent++;
      ++na;
    }


    /* Loop until all targets have replied, or we timeout */
    while (na) {
      int np;

      /* Build list of FDs to listen for packets on */
      np = 0;
      for (tp = tlist; tp; tp = tp->next) {
        int k;

        /* FD already in use? */
        for (k = 0; k < np && pfdv[k].fd != tp->fd; k++)
          ;

        if (tp->t1.tv_sec == 0 && tp->t1.tv_nsec == 0) {
	  if (k == np) {
	    pfdv[np].fd = tp->fd;
	    pfdv[np].events = POLLIN;
	    pfdv[np].revents = 0;
	    ++np;
	  }
        }
      }


      /* Calculate how long to sleep max */
      clock_gettime(CLOCK_REALTIME, &t1);
      td = f_timeout-diff_timespec(&t1, &t0);
      if (td < 0)
        td = 0;

      if (f_verbose > 2)
        printf("Polling for %f ms\n", td*1000);

      /* Wait for response packets or alarm timeout */
      rc = poll(&pfdv[0], np, td*1000);
      if (rc < 0) {
        if (errno == EINTR) {
          goto End;
        } else {
          fprintf(stderr, "%s: Error: poll: %s\n",
                  argv[0], strerror(errno));
          exit(1);
        }
      } else if (rc == 0)
        goto End;

      for (j = 0; j < np; j++) {
        if (pfdv[j].revents & POLLIN) {
          /* Clear out response sender address */
          fromp = (struct sockaddr *) &frombuf;
          flen = sizeof(frombuf);
          memset(fromp, 0, flen);

          memset(rbuf, 0, sizeof(rbuf));

          /* Receive response */
          rlen = rc = recvfrom(pfdv[j].fd, rbuf, sizeof(rbuf), 0, fromp, &flen);
          if (rc < 0) {
            if (errno == EINTR)
              goto End;
            fprintf(stderr, "%s: Error: recvfrom: %s\n",
                    argv[0], strerror(errno));
            exit(1);
          }

          clock_gettime(CLOCK_REALTIME, &t1);

          /* Get printable IP address */
          rc = getnameinfo(fromp, flen,
                           hbuf, sizeof(hbuf),
                           NULL, 0, NI_NUMERICHOST);
          /* XXX: Handle err from getnameinfo() */


          /* Locate response sender in list of targets */
          for (tp = tlist; tp; tp = tp->next) {
            if (flen == tp->ai->ai_addrlen && memcmp(tp->ai->ai_addr, fromp, flen) == 0) {
              break;
	    }
          }

          /* Unknown sender */
          if (!tp) {
            if (f_verbose > 1) {
              fprintf(stderr, "%s: Error: %s: Spurious packet received (ignored)\n",
                      argv[0], hbuf);
              if (f_display) {
                int offset = 0;
                rc = display_buffer(stderr, rbuf+offset, rlen-offset);
              }
            }
            continue;
          }


          /* Validate response */
          if (pp->response) {
            int offset = (tp->ai->ai_protocol == IPPROTO_ICMP && rlen > 20 ? 20 : 0);

            rc = pp->response(tp, seq, &t1, rbuf+offset, rlen-offset);
            if (rc) {
              if (f_verbose) {
                fprintf(stderr, "%s: Error: %s: Invalid response: RC=%d\n",
                        argv[0], hbuf, rc);
                if (f_display)
                  rc = display_buffer(stderr, rbuf+offset, rlen-offset);
              }
	      if (rc < 0)
		continue;
            }
	  }


          tp->t1 = t1;
          rtt = diff_timespec(&tp->t1, &tp->t0);
          if (tp->rtt.min < 0 || rtt < tp->rtt.min)
            tp->rtt.min = rtt;
          if (rtt > tp->rtt.max)
            tp->rtt.max = rtt;
          tp->rtt.sum += rtt;

          /* Print valid response */
          if (!f_silent) {
	    FILE *outfp = (rc ? stderr : stdout);
	    int offset = (tp->ai->ai_protocol == IPPROTO_ICMP && rlen > 20 ? 20 : 0);

            print_timespec(outfp, &t1);
            fprintf(outfp, " : %-*s : ", addrlen, tp->addr);
            if (!f_numeric)
              fprintf(outfp, "%-*s : ", namelen, tp->name);
            fprintf(outfp, "seq=%u : rtt=%.3f ms", seq, rtt*1000);
	    if (rc)
	      fprintf(outfp, " : rc=%d", rc);
            if (f_verbose)
              fprintf(outfp, " : len=%d : missed=%lu", rlen-offset, tp->packets.missed);
            putc('\n', outfp);
            if (f_display) {
              rc = display_buffer(outfp, rbuf+offset, rlen-offset);
            }
          }
          tp->packets.missed = 0;
          --na;
        }
      }
    }

  End:
    /* Disable timeout */
    alarm(0);

    /* Get current time */
    clock_gettime(CLOCK_REALTIME, &t1);

    /* Print missed responses */
    for (tp = tlist; tp; tp = tp->next) {
      if (tp->t1.tv_sec == 0 && tp->t1.tv_nsec == 0) {
        if (!f_silent || (tp->packets.missed >= f_warning ||
                          tp->packets.missed >= f_critical)) {
	  FILE *outfp = (tp->packets.missed >= f_critical ? stderr : stdout);

          print_timespec(outfp, &t1);
          fprintf(outfp, " : %-*s : ", addrlen, tp->addr);
          if (!f_numeric)
            fprintf(outfp, "%-*s : ", namelen, tp->name);
          fprintf(outfp, "seq=%u : missed=%lu : Timeout\n", seq, tp->packets.missed);
        }
        tp->packets.missed++;
      }
    }

    /* Sleep until next time */
    if (f_cont < 0 || (f_cont && --f_cont)) {
      /* Get current time */
      clock_gettime(CLOCK_REALTIME, &t1);

      td = f_interval-diff_timespec(&t1, &t0);
      if (td > 0) {
        if (f_verbose > 2)
          printf("Sleeping %f ms\n", td*1000);
        usleep(td*1000000);
      }
    }

    /* Increase sequence counter */
    ++seq;
  } while (!got_sigint && f_cont);

  if (f_summary || f_verbose) {
    unsigned long sent = 0;
    unsigned long missed = 0;
    double rtt_min = -1;
    double rtt_avg = 0;
    double rtt_max = 0;
    int nt = 0;

    for (tp = tlist; tp; tp = tp->next) {
      sent   += tp->packets.sent;
      missed += tp->packets.missed;

      if (rtt_min < 0 || tp->rtt.min < rtt_min)
        rtt_min = tp->rtt.min;
      if (tp->rtt.max > rtt_max)
        rtt_max = tp->rtt.max;
      rtt_avg += tp->rtt.sum;
      ++nt;
    }

    rtt_avg /= (sent-missed);

    printf("[packets: %lu sent, %lu received, %.0f%% packet loss; ",
           sent, sent-missed, (missed*1.0/sent));
    printf("rtt(ms): %.3f min, %.3f avg, %.3f max]\n",
           rtt_min*1000.0, rtt_avg*1000.0, rtt_max*1000.0);
  }
}
