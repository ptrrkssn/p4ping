/*
 * p4ping.c
 *
 * Copyright (c) 2023 Peter Eriksson <pen@lysator.liu.se>
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
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>


char *version = PACKAGE_VERSION;

char *f_protocol = "icmp";
char *f_service = NULL;

int f_family = AF_UNSPEC;
int f_timeout = 1;
int f_interval = 1;
int f_tcp = 0;
int f_cont = 0;
int f_ndelay = 0;
int f_verbose = 0;
int f_script = 0;
int f_numeric = 0;
int f_silent = 0;
int f_ttl = 0;
int f_display = 0;


double
diff_timespec(struct timespec *t0,
              struct timespec *t1) {
  return (t0->tv_sec-t1->tv_sec) + (t0->tv_nsec-t1->tv_nsec)/1000000000.0;
}

int
print_timespec(struct timespec *ts) {
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
  len -= rc - 1;

  rc = snprintf(buf+strlen(buf), len, (f_verbose ? ".%09ld" : ".%03ld"), f_verbose ? ts->tv_nsec : ts->tv_nsec/1000000);
  if (rc >= len)
    return -1;

  return fputs(buf, stdout);
}


void
sigalrm_handler(int sig) {
}



typedef struct target {
  int fd;
  char *addr;
  char *name;
  struct addrinfo *ai;
  struct timespec t0;
  struct timespec t1;
  unsigned int missed;
  struct target *next;
} TARGET;

TARGET *tlist = NULL;



#define ICMP_ECHO_MAGIC "1234567890"
#define ICMP_ECHO_MAGIC_LEN 11

struct icmp_echo {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t ident;
  uint16_t seq;
  double ts;
  char magic[ICMP_ECHO_MAGIC_LEN];
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
                       int seq,
                       struct timespec *t) {
  struct icmp_echo ep;
  short ident = 0;

  memset(&ep, 0, sizeof(ep));
  ep.type = (tp->ai->ai_family == AF_INET ? 8 : 128);
  ep.code = 0;
  ep.ident = htons(ident);
  ep.seq = htons(seq);
  strncpy(ep.magic, ICMP_ECHO_MAGIC, ICMP_ECHO_MAGIC_LEN);
  ep.ts = t->tv_sec+(t->tv_nsec/1000000000.0);
  ep.checksum = htons(calc_checksum((unsigned char *) &ep, sizeof(ep)));

  return sendto(tp->fd, &ep, sizeof(ep), 0, tp->ai->ai_addr, tp->ai->ai_addrlen);
}

int
send_ntp_request(struct target *tp,
                 int seq,
                 struct timespec *t) {
  unsigned char tbuf[48];

  memset(tbuf, 0, sizeof(tbuf));
  tbuf[0] = 0x1B;

  return sendto(tp->fd, tbuf, sizeof(tbuf), 0, tp->ai->ai_addr, tp->ai->ai_addrlen);
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

int
send_dns_request(struct target *tp,
                 int seq,
                 struct timespec *t) {
  struct dns_header req;

  memset(&req, 0, sizeof(req));
  req.id = htons(seq);
  req.opcode = 0; /* 0 = Query, 1 = Inverse Query, 2 = Server status */

  return sendto(tp->fd, (void *) &req, sizeof(req), 0, tp->ai->ai_addr, tp->ai->ai_addrlen);
}

int
send_udp_request(struct target *tp,
                 int seq,
                 struct timespec *t) {
  unsigned char tbuf[512];

  memset(tbuf, 0, sizeof(tbuf));
  return sendto(tp->fd, tbuf, sizeof(tbuf), 0, tp->ai->ai_addr, tp->ai->ai_addrlen);
}


int
display_buffer(void *buf,
		 size_t buflen) {
  unsigned char *bufp = (unsigned char *) buf;
  unsigned char *endp = bufp+buflen;
  int i;

  while (bufp < endp) {
    putchar('\t');
    for (i = 0; i < 16 && bufp+i < endp; i++) {
      if (i > 0)
	putchar(' ');
      if (i == 8)
	putchar(' ');
      printf("%02x", bufp[i]);
    }
    while (i++ < 16) {
      fputs("   ", stdout);
    }

    putchar('\t');
    for (i = 0; i < 16 && bufp < endp; i++) {
      if (i > 0)
	putchar(' ');
      if (i == 8)
	putchar(' ');
      putchar(isprint(*bufp) ? *bufp : '?');
      ++bufp;
    }
    
    putchar('\n');
  }

  return 0;
}

struct protocol {
  char *name;
  int ai_socktype;
  int ai_protocol;
  char *ai_service;
  int (*setup)(struct addrinfo *aip);
  int (*request)(struct target *tp, int seq, struct timespec *t0);
  int (*response)(struct target *tp, int seq, struct timespec *t0, void *buf, size_t buflen);
} protocols[] = {
  { "icmp",
    SOCK_RAW, IPPROTO_ICMP, NULL,
    NULL, send_icmp_echo_request, NULL },
  { "ntp",
    SOCK_DGRAM, 0, "ntp",
    NULL, send_ntp_request, NULL },
  { "dns",
    SOCK_DGRAM, 0, "domain",
    NULL, send_dns_request, NULL },
  { "udp",
    SOCK_DGRAM, IPPROTO_UDP, "echo",
    NULL, send_udp_request, NULL },
  { NULL,
    -1, -1,
    NULL, NULL, NULL }
};

int
main(int argc,
     char *argv[]) {
  int rc, i, j, k, n, v, rlen;
  unsigned int seq;
  unsigned char rbuf[9000];
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


  for (i = 1; i < argc && argv[i][0] == '-'; i++) {
    for (j = 1; argv[i][j]; j++) {
      switch (argv[i][j]) {
      case 'h':
        printf("Usage:\n\t%s [<options>] <host>\n", argv[0]);
        puts("  -h            Display this information");
        puts("  -v            Be more verbose");
        puts("  -s            Be silent");
        puts("  -c            Continous ping");
        puts("  -f            Flood ping");
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
        puts("  -S<service>   Force IP service (port) number");
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
      case 's':
        f_silent++;
        break;
      case 'c':
        f_cont++;
        break;
      case 'f':
        f_ndelay++;
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
    printf("[p4ping, version %s - Copyright (c) 2023 Peter Eriksson <pen@lysator.liu.se>]\n", version);
  
 EndArg:
  if (i >= argc) {
    fprintf(stderr, "%s: Error: Missing required <hosts> arguments\n", argv[0]);
    exit(1);
  }

  for (j = 0; protocols[j].name && strcmp(protocols[j].name, f_protocol) != 0; j++)
    ;
  if (!protocols[j].name) {
    fprintf(stderr, "%s: Error: %s: Invalid protocol\n",
            argv[0], f_protocol);
    exit(1);
  }
  pp = &protocols[j];

  pfdn = 0;
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


    for (rp = result; rp != NULL; rp = rp->ai_next) {
      if (rp->ai_family == AF_INET6 && pp->ai_protocol == IPPROTO_ICMP)
        rp->ai_protocol = IPPROTO_ICMPV6;

      int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (fd == -1) {
        fprintf(stderr, "%s: Error: %s: socket: %s\n",
                argv[0], argv[i], strerror(errno));
        continue;
      }

      if (f_ttl) {
        rc = setsockopt(fd, IPPROTO_IP, IP_TTL, &f_ttl, sizeof(f_ttl));
        if (rc < 0) {
          fprintf(stderr, "%s: Error: %s: setsockopt(IP_TTL): %s\n",
                  argv[0], argv[i], strerror(errno));
          exit(1);
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

  seq = 0;
  do {
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigalrm_handler;
    sigaction(SIGALRM, &sa, NULL);

    alarm(f_timeout);
    clock_gettime(CLOCK_REALTIME, &t0);


    if (f_verbose > 1)
      puts("Sending requests");

    n = 0;
    for (tp = tlist; tp; tp = tp->next) {
      rc = pp->request(tp, seq, &t0);
      if (rc < 0) {
        fprintf(stderr, "%s: Error: %s [%s]: send-request: %s\n",
                argv[0], tp->addr, tp->name, strerror(errno));
        exit(1);
      }

      tp->t0 = t0;
      n++;
    }

    while (n) {
      n = 0;
      for (tp = tlist; tp; tp = tp->next) {
        if (tp->t0.tv_sec) {
          pfdv[n].fd = tp->fd;
          pfdv[n].events = POLLIN;
          pfdv[n].revents = 0;
          n++;
        }
      }

      if (f_verbose > 1)
        printf("Waiting for %d responses:\n", n);

      clock_gettime(CLOCK_REALTIME, &t1);
      td = 1.0-diff_timespec(&t1, &t0);
      if (td < 0)
        td = 0;

      rc = poll(&pfdv[0], n, td*1000);
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

      for (j = 0; j < n; j++) {
        if (pfdv[j].revents & POLLIN) {
          for (tp = tlist; tp && tp->fd != pfdv[j].fd; tp = tp->next)
            ;
          if (!tp) {
            fprintf(stderr, "%s: Error: Foo!\n", argv[0]);
            exit(1);
          }

          fromp = (struct sockaddr *) &frombuf;
          flen = sizeof(frombuf);
          memset(fromp, 0, flen);

          memset(rbuf, 0, sizeof(rbuf));
          rc = recvfrom(tp->fd, rbuf, sizeof(rbuf), 0, fromp, &flen);
          if (rc < 0) {
            if (errno == EINTR) {
              goto End;
            } else {
              fprintf(stderr, "%s: Error: %s [%s]: recvfrom: %s\n",
                      argv[0], tp->addr, tp->name, strerror(errno));
              exit(1);
            }
          }
	  rlen = rc;

          if (flen != tp->ai->ai_addrlen ||
              memcmp(tp->ai->ai_addr, fromp, flen) != 0) {
            rc = getnameinfo(fromp, flen,
                             hbuf, sizeof(hbuf),
                             NULL, 0, NI_NUMERICHOST);
            /* XXX: Handle err from getnameinfo() */
            fprintf(stderr, "%s: Error: %s: Spurious response (ignored)\n",
                    argv[0], hbuf);
	    if (f_display) {
	      int offset = 0; /* (tp->ai->ai_protocol == IPPROTO_ICMP && rlen > 20 ? 20 : 0); */
	      rc = display_buffer(rbuf+offset, rlen-offset);
	    }
            continue;
          }


          if (pp->response) {
            rc = pp->response(tp, seq, &t1, rbuf, rlen);
	  }


          clock_gettime(CLOCK_REALTIME, &t1);
          tp->t1 = t1;
          rtt = diff_timespec(&t1, &t0);
          print_timespec(&t1);
          printf(" : %-*s : ", addrlen, tp->addr);
          if (!f_numeric)
            printf("%-*s : ", namelen, tp->name);
          printf("seq=%u : rtt=%.3f ms", seq, rtt*1000);
          if (f_verbose)
            printf(" : len=%d : missed=%u", rc, tp->missed);
          putchar('\n');
          tp->t0.tv_sec = 0;
          tp->missed = 0;
          n--;

	  if (f_display) {
	    int offset = (tp->ai->ai_protocol == IPPROTO_ICMP && rlen > 20 ? 20 : 0);
            rc = display_buffer(rbuf+offset, rlen-offset);
	  }
        }
      }
    }

  End:
    alarm(0);

    clock_gettime(CLOCK_REALTIME, &t1);
    if (rc < 0 && errno == EINTR) {
      for (tp = tlist; tp; tp = tp->next) {
        if (tp->t0.tv_sec) {
          print_timespec(&t1);
          printf(" : %-*s : ", addrlen, tp->addr);
          if (!f_numeric)
            printf("%-*s : ", namelen, tp->name);
          printf("seq=%u : Timeout\n", seq);
          tp->t0.tv_sec = 0;
          tp->missed++;
          n--;
        }
      }
    }

    if (f_cont) {
      td = f_interval-diff_timespec(&t1, &t0);
      if (td > 0) {
        if (f_verbose > 1)
          printf("Sleeping %f ms\n", td*1000);
        usleep(td*1000000);
      }
    }

    seq++;
  } while (f_cont);
}
