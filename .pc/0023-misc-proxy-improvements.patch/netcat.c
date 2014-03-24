/* $OpenBSD: netcat.c,v 1.105 2012/02/09 06:25:35 lum Exp $ */
/*
 * Copyright (c) 2001 Eric Jackson <ericj@monkey.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Re-written nc(1) for OpenBSD. Original implementation by
 * *Hobbit* <hobbit@avian.org>.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/telnet.h>
#include <arpa/inet.h>

#ifndef IPTOS_LOWDELAY
# define IPTOS_LOWDELAY 0x10
# define IPTOS_THROUGHPUT 0x08
# define IPTOS_RELIABILITY 0x04
# define IPTOS_LOWCOST 0x02
# define IPTOS_MINCOST IPTOS_LOWCOST
#endif /* IPTOS_LOWDELAY */

# ifndef IPTOS_DSCP_AF11
# define	IPTOS_DSCP_AF11		0x28
# define	IPTOS_DSCP_AF12		0x30
# define	IPTOS_DSCP_AF13		0x38
# define	IPTOS_DSCP_AF21		0x48
# define	IPTOS_DSCP_AF22		0x50
# define	IPTOS_DSCP_AF23		0x58
# define	IPTOS_DSCP_AF31		0x68
# define	IPTOS_DSCP_AF32		0x70
# define	IPTOS_DSCP_AF33		0x78
# define	IPTOS_DSCP_AF41		0x88
# define	IPTOS_DSCP_AF42		0x90
# define	IPTOS_DSCP_AF43		0x98
# define	IPTOS_DSCP_EF		0xb8
#endif /* IPTOS_DSCP_AF11 */

#ifndef IPTOS_DSCP_CS0
# define	IPTOS_DSCP_CS0		0x00
# define	IPTOS_DSCP_CS1		0x20
# define	IPTOS_DSCP_CS2		0x40
# define	IPTOS_DSCP_CS3		0x60
# define	IPTOS_DSCP_CS4		0x80
# define	IPTOS_DSCP_CS5		0xa0
# define	IPTOS_DSCP_CS6		0xc0
# define	IPTOS_DSCP_CS7		0xe0
#endif /* IPTOS_DSCP_CS0 */

#ifndef IPTOS_DSCP_EF
# define	IPTOS_DSCP_EF		0xb8
#endif /* IPTOS_DSCP_EF */


#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <ctype.h>
#include <bsd/stdlib.h>
#include <bsd/string.h>
#include <sys/wait.h>
#include "atomicio.h"

#ifndef SUN_LEN
#define SUN_LEN(su) \
	(sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

#define PORT_MAX	65535
#define PORT_MAX_LEN	6
#define UNIX_DG_TMP_SOCKET_SIZE	19
#define PROXY_CHAIN_MAX 32
#define SOCKS_PORT	"1080"
#define HTTP_PROXY_PORT	"3128"

#define CONNECTION_SUCCESS 0
#define CONNECTION_FAILED 1
#define CONNECTION_TIMEOUT 2

#define UDP_SCAN_TIMEOUT 3			/* Seconds */

#define LISTEN_BACKLOG 5

char *PROXY = "proxy";
char *ZIP = "zip";
char *MATCH = "match";

/* Command Line Options */
int	bflag;					/* Allow Broadcast */
int     Cflag = 0;                              /* CRLF line-ending */
int	dflag;					/* detached, no stdin */
unsigned int iflag;				/* Interval Flag */
int	jflag;					/* use jumbo frames if we can */
int	kflag;					/* More than one connect */
int	lflag;					/* Bind to local port */
int	mflag;					/* max. child processes to fork */
int	nflag;					/* Don't do name look up */
char   *Pflag;					/* Proxy username */
char   *pflag;					/* Localport flag */
int     qflag = 0;                              /* Quit after ... */
int	qtime = 0;				/* ... this many seconds */
int	rflag;					/* Random ports flag */
char   *sflag;					/* Source Address */
int	tflag;					/* Telnet Emulation */
int	uflag;					/* UDP - Default to TCP */
int	dccpflag;				/* DCCP - Default to TCP */
int	vflag;					/* Verbosity */
int	xflag;					/* Socks proxy */
int	zflag;					/* Port Scan Flag */
int	Dflag;					/* sodebug */
int	Iflag;					/* TCP receive buffer size */
int	Oflag;					/* TCP send buffer size */
int	Sflag;					/* TCP MD5 signature option */
int	Tflag = -1;				/* IP Type of Service */
u_int	rtableid;

int timeout = -1;
int family = AF_UNSPEC;
char *portlist[PORT_MAX+1];
char *hostlist[PORT_MAX+1];
int num_destinations = 0;
struct pollfd listen_poll[PORT_MAX+1];
char *unix_dg_tmp_socket;
int broker_socket;

void	atelnet(int, unsigned char *, unsigned int);
void	build_hosts_and_ports(int argc, char *argv[]);
void	help(void);
int	local_listen(char *, char *, struct addrinfo);
void	readwrite(int);
int	recursive_connect(const char *, const char *, struct addrinfo,
	    const char *[], const char *[], struct addrinfo, int, const char *, char*);
int	proxy_read_connection_request(int request_sock, char **host, char **port);
void	proxy_send_error_reply(int request_sock, int proxy_proto);
void	proxy_send_success_reply(int request_sock, int proxy_proto, int peer_sock);
int	udptest(int);
int	unix_bind(char *);
int	unix_connect(char *);
int	unix_listen(char *);
void	set_common_sockopts(int);
int	map_tos(char *, int *);
void	usage(int);
char    *proto_name(int uflag, int dccpflag);
const char    *af_name(short af);

static int connect_with_timeout(int fd, const struct sockaddr *sa,
        socklen_t salen, int ctimeout);
static void connection_broker();
static void connect_stdin_stdout_to(int request_sock, int destination_idx, const char *endpoint2host, const char *endpoint2port,
	struct addrinfo hints, const char *proxyhost[], const char *proxyport[],
	struct addrinfo proxyhints, int socksv, const char *proxyuser, char *headers);
static void shutdown_endpoint2(const char *endpoint2host);
static void quit();

int	child_count = 0;
static	int handle_mflag(void) {
	int childpid;
	
	if (!mflag)
		return 0;
	
	if (child_count == mflag) {
		for (; waitpid(-1, NULL, 0) < 0;) {
			if (errno != EINTR) {
				warn("waitpid");
				sleep(1); /* wait a little before returning to the main loop */
				return 1;
			}
		}
		--child_count;
	}
	
	childpid = fork();
	if (childpid < 0) {
		warn("fork");
		sleep(1); /* wait a little before returning to the main loop */
		return 1;
	}
	
	if (childpid == 0) { /* inside the child process */
		kflag = 0;   /* the child must not loop */
		return 0;
	}
	
	++child_count;
	return 1;
}

int
main(int argc, char *argv[])
{
	int ch, s, ret, socksv;
	char *cptr;
	struct addrinfo hints;
	struct servent *sv;
	socklen_t len;
	union {
        	struct sockaddr_storage storage;
		struct sockaddr_un forunix;
	} cliaddr;
	char *proxy = NULL;
	const char *errstr;
	const char *proxyhost[PROXY_CHAIN_MAX+1] = {NULL};
	const char *proxyport[PROXY_CHAIN_MAX+1] = {NULL};
	char *endpoint2 = NULL;
	char *endpoint2host = NULL, *endpoint2port = NULL;
	char* headers = NULL;
	struct addrinfo proxyhints;
	char unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	sv = NULL;

	while ((ch = getopt(argc, argv,
	    "2:46bCDdhH:I:i:jklm:nO:P:p:q:rSs:tT:UuV:vw:X:x:Zz")) != -1) {
		switch (ch) {
		case '2':
			if ((endpoint2 = strdup(optarg)) == NULL)
				err(1, NULL);
			break;
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 'b':
# if defined(SO_BROADCAST)
			bflag = 1;
# else
			errx(1, "no broadcast frame support available");
# endif
			break;
		case 'U':
			family = AF_UNIX;
			break;
		case 'X':
			if (strcasecmp(optarg, "connect") == 0)
				socksv = -1; /* HTTP proxy CONNECT */
			else if (strcmp(optarg, "4") == 0)
				socksv = 4; /* SOCKS v.4 */
			else if (strcmp(optarg, "5") == 0)
				socksv = 5; /* SOCKS v.5 */
			else
				errx(1, "unsupported proxy protocol");
			break;
		case 'H':
			cptr = index(optarg, ':');
			if (cptr == NULL)
				errx(1, "missing ':' in -H argument: %s", optarg);

			if (headers == NULL)
				headers = malloc(strlen(optarg) + 1 + 2 + 1); /* space, \r\n, \0 */
			else
				headers = realloc(headers, strlen(headers) + strlen(optarg) + 1 + 2 + 1);

			if (headers == NULL)
				err(1, NULL);

			strncat(headers, optarg, cptr-optarg);
			strcat(headers, ": ");
			strcat(headers, cptr+1);
			strcat(headers, "\r\n");
			break;
		case 'd':
			dflag = 1;
			break;
		case 'h':
			help();
			break;
		case 'i':
			iflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			if (errstr)
				errx(1, "interval %s: %s", errstr, optarg);
			break;
		case 'j':
# if defined(SO_JUMBO)
			jflag = 1;
# else
			errx(1, "no jumbo frame support available");
# endif
			break;
		case 'k':
			kflag = 1;
			break;
		case 'l':
			lflag = 1;
			break;
                case 'm':
			mflag = strtonum(optarg, 0, UINT_MAX, &errstr);
			if (errstr)
				errx(1, "-m value %s: %s", errstr, optarg);
			break;
		case 'n':
			nflag = 1;
			break;
		case 'P':
			Pflag = optarg;
			break;
		case 'p':
			pflag = optarg;
			break;
                case 'q':
			qflag = 1;
			qtime = strtonum(optarg, INT_MIN, INT_MAX, &errstr);
			if (errstr)
				errx(1, "quit timer %s: %s", errstr, optarg);
			break;
		case 'r':
			rflag = 1;
			break;
		case 's':
			sflag = optarg;
			break;
		case 't':
			tflag = 1;
			break;
		case 'u':
			uflag = 1;
			break;
		case 'Z':
# if defined(IPPROTO_DCCP) && defined(SOCK_DCCP)
			dccpflag = 1;
# else
			errx(1, "no DCCP support available");
# endif
			break;
		case 'V':
# if defined(RT_TABLEID_MAX)
			rtableid = (unsigned int)strtonum(optarg, 0,
			    RT_TABLEID_MAX, &errstr);
			if (errstr)
				errx(1, "rtable %s: %s", errstr, optarg);
# else
			errx(1, "no alternate routing table support available");
# endif
			break;
		case 'v':
			vflag = 1;
			break;
		case 'w':
			timeout = strtonum(optarg, 0, INT_MAX / 1000, &errstr);
			if (errstr)
				errx(1, "timeout %s: %s", errstr, optarg);
			timeout *= 1000;
			break;
		case 'x':
			xflag = 1;
			if ((proxy = strdup(optarg)) == NULL)
				err(1, NULL);
			break;
		case 'z':
			zflag = 1;
			break;
		case 'D':
			Dflag = 1;
			break;
		case 'I':
			Iflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			if (errstr != NULL)
				errx(1, "TCP receive window %s: %s",
				    errstr, optarg);
			break;
		case 'O':
			Oflag = strtonum(optarg, 1, 65536 << 14, &errstr);
			if (errstr != NULL)
				errx(1, "TCP send window %s: %s",
				    errstr, optarg);
			break;
		case 'S':
# if defined(TCP_MD5SIG)
			Sflag = 1;
# else
			errx(1, "no TCP MD5 signature support available");
# endif
			break;
		case 'T':
			errstr = NULL;
			errno = 0;
			if (map_tos(optarg, &Tflag))
				break;
			if (strlen(optarg) > 1 && optarg[0] == '0' &&
			    optarg[1] == 'x')
				Tflag = (int)strtol(optarg, NULL, 16);
			else
				Tflag = (int)strtonum(optarg, 0, 255,
				    &errstr);
			if (Tflag < 0 || Tflag > 255 || errstr || errno)
				errx(1, "illegal tos value %s", optarg);
			break;
                case 'C':
                        Cflag = 1;
                        break;
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	/* Cruft to make sure options are clean, and used properly. */
# if defined(IPPROTO_DCCP) && defined(SOCK_DCCP)
	if (dccpflag && family == AF_UNIX)
		errx(1, "cannot use -Z and -U");
# endif

	if (argc == 0)
		usage(1);

	if (lflag) {
		if (sflag)
			errx(1, "cannot use -s and -l");
		if (zflag)
			errx(1, "cannot use -z and -l");
		if (pflag)
			errx(1, "cannot use -p and -l");
	}

	if (mflag && uflag)
		errx(1, "cannot use -m with -u");

	/* Construct the portlist[] and hostlist[] arrays. */
	build_hosts_and_ports(argc, argv);

	/* Get name of temporary socket for unix datagram client */
	if ((family == AF_UNIX) && uflag && !lflag) {
		if (sflag) {
			unix_dg_tmp_socket = sflag;
		} else {
			strlcpy(unix_dg_tmp_socket_buf, "/tmp/nc.XXXXXXXXXX",
				UNIX_DG_TMP_SOCKET_SIZE);
			if (mkstemp(unix_dg_tmp_socket_buf) == -1)
				err(1, "mkstemp");
			unix_dg_tmp_socket = unix_dg_tmp_socket_buf;
		}
	}

	/* Initialize addrinfo structure. */
	if (family != AF_UNIX) {
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = family;
		if (uflag) {
		    hints.ai_socktype = SOCK_DGRAM;
		    hints.ai_protocol = IPPROTO_UDP;
		}
# if defined(IPPROTO_DCCP) && defined(SOCK_DCCP)
		else if (dccpflag) {
		    hints.ai_socktype = SOCK_DCCP;
		    hints.ai_protocol = IPPROTO_DCCP;
		}
# endif
		else {
		    hints.ai_socktype = SOCK_STREAM;
		    hints.ai_protocol = IPPROTO_TCP;
		}
		if (nflag)
			hints.ai_flags |= AI_NUMERICHOST;
	}

	if (xflag) {
		int i;
		int proxycount;
		char* proxypart;
		char* phost;
		char* pport;

		for(i = 0; i < PROXY_CHAIN_MAX ; ++i) {
			proxypart = strsep(&proxy, "+");
			if (proxypart == NULL) {
				proxyhost[i] = NULL;
				proxyport[i] = NULL;
				break;
			}

			phost = strsep(&proxypart, ":");
			if (proxypart == NULL || *proxypart == 0)
				pport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;
			else
				pport = proxypart;

			if (*phost == 0)
				errx(1, "missing proxy host name");
			proxyhost[i] = phost;
			proxyport[i] = pport;
		}

		proxycount = i;
		if (proxycount >= PROXY_CHAIN_MAX)
			errx(1, "proxy chain too long");

		proxy = (char*)proxyhost[0]; /* restore original pointer in case someone wants to free() it. */

		/* Reverse proxy chain so that exit proxy is element 0 */
		for (i = 0; i < (proxycount >> 1); ++i) {
			const char* tmp = proxyhost[i];
			proxyhost[i] = proxyhost[proxycount - i - 1];
			proxyhost[proxycount - i - 1] = tmp;
			tmp = proxyport[i];
			proxyport[i] = proxyport[proxycount - i - 1];
			proxyport[proxycount - i - 1] = tmp;
		}

		if (uflag)
			errx(1, "no proxy support for UDP mode");
# if defined(IPPROTO_DCCP) && defined(SOCK_DCCP)
		if (dccpflag)
			errx(1, "no proxy support for DCCP mode");
# endif
		if (lflag)
			errx(1, "no proxy support for listen");

		if (family == AF_UNIX)
			errx(1, "no proxy support for unix sockets");

		/* XXX IPv6 transport to proxy would probably work */
		if (family == AF_INET6)
			errx(1, "no proxy support for IPv6");

		if (sflag)
			errx(1, "no proxy support for local source address");


		memset(&proxyhints, 0, sizeof(struct addrinfo));
		proxyhints.ai_family = family;
		proxyhints.ai_socktype = SOCK_STREAM;
		proxyhints.ai_protocol = IPPROTO_TCP;
		if (nflag)
			proxyhints.ai_flags |= AI_NUMERICHOST;
	}

	if (endpoint2 != NULL) {
		if (uflag)
			errx(1, "no 2nd endpoint support for UDP mode");

		/* Make it possible to use == and != instead of strcmp() */
		if (strcmp(endpoint2, PROXY) == 0)
			endpoint2 = PROXY;
                else if (strcmp(endpoint2, ZIP) == 0) {
			if (mflag < 2)
				errx(1, "-2 zip requires -m 2 or higher");
			if (num_destinations < 2)
				errx(1, "-2 zip requires at least 2 destinations");
			endpoint2 = ZIP;
			connection_broker();
		} else if (strcmp(endpoint2, MATCH) == 0) {
			if (mflag < 2)
				errx(1, "-2 match requires -m 2 or higher");
			if (num_destinations < 2)
				errx(1, "-2 match requires at least 2 destinations");
			endpoint2 = MATCH;
			connection_broker();
		}

		endpoint2port = strrchr(endpoint2, ':');
		endpoint2host = endpoint2;
		if (endpoint2port == NULL) {
			if (endpoint2 != PROXY && endpoint2 != ZIP && endpoint2 != MATCH)
				errx(1, "port missing in -2 address: %s", endpoint2);
		} else
			*endpoint2port++ = 0;
	}

	if (lflag) {
		int connfd;
		int i;
		ret = 0;

		for (i = 0; i < num_destinations; ++i) {
			if (family == AF_UNIX) {
				if (uflag)
					s = unix_bind(hostlist[i]);
				else
					s = unix_listen(hostlist[i]);
			} else
				s = local_listen(hostlist[i], portlist[i], hints);
			if (s < 0)
				err(1, NULL);

			char* local;
			if (family == AF_INET6)
				local = ":::";
			else
				local = "0.0.0.0";
			if (vflag && (family != AF_UNIX))
			fprintf(stderr, "Listening on [%s] (family %d, port %s)\n",
				hostlist[i] ?: local,
				family,
				portlist[i]);

			// according to poll(2) on Linux poll() may return
			// spurious readiness info, so set O_NONBLOCK to be safe.
			if (fcntl(s, F_SETFL, O_NONBLOCK) < 0)
				err(1, "fcntl");
			listen_poll[i].fd = s;
			listen_poll[i].events = POLLIN;
		}

		for (;;) {
		  int pollnum = poll(listen_poll, num_destinations, -1);
		  if (pollnum < 0 && errno != EINTR)
			err(1, "poll");

		  if (pollnum <= 0)
			continue;

		  for (i = 0; i < num_destinations; ++i) {
		    if ((listen_poll[i].revents & POLLIN) != 0) {
                    	s = listen_poll[i].fd;

			/*
			 * For UDP, we will use recvfrom() initially
			 * to wait for a caller, then use the regular
			 * functions to talk to the caller.
			 */
			if (uflag) {
				int rv, plen;
				char buf[16384];

				len = sizeof(cliaddr);
				plen = jflag ? 16384 : 2048;
				rv = recvfrom(s, buf, plen, MSG_PEEK,
				    (struct sockaddr *)&cliaddr, &len);
				if (rv < 0) {
					if (errno == EAGAIN || errno == EINTR)
						continue;
					err(1, "recvfrom");
				}

				rv = connect(s, (struct sockaddr *)&cliaddr, len);
				if (rv < 0)
					err(1, "connect");

				readwrite(s);
			} else {
				len = sizeof(cliaddr);
				connfd = accept(s, (struct sockaddr *)&cliaddr, &len);
				if (connfd < 0 && (errno == EINTR || errno == EAGAIN))
					continue;
				if (handle_mflag()) {
					close(connfd);	/* close connfd in the parent process */
					if (vflag)
						fprintf(stderr, "Forked child process to handle connection, listening again.\n");
					continue;
                                }
                                if (connfd < 0)
                                	err(1, "accept");
				if(vflag && family == AF_UNIX) {
					fprintf(stderr, "Connection from \"%.*s\" accepted\n",
						(len - (int)offsetof(struct sockaddr_un, sun_path)),
						((struct sockaddr_un*)&cliaddr)->sun_path);
				} else if(vflag) {
					char *proto = proto_name(uflag, dccpflag);
				/* Don't look up port if -n. */
					if (nflag)
						sv = NULL;
					else
						sv = getservbyport(ntohs(atoi(portlist[i])),
							proto);

					if (((struct sockaddr *)&cliaddr)->sa_family == AF_INET) {
						char dst[INET_ADDRSTRLEN];
						inet_ntop(((struct sockaddr *)&cliaddr)->sa_family,&(((struct sockaddr_in *)&cliaddr)->sin_addr),dst,INET_ADDRSTRLEN);
						fprintf(stderr, "Connection from [%s] port %s [%s/%s] accepted (family %d, sport %d)\n",
							dst,
							portlist[i],
							proto,
							sv ? sv->s_name : "*",
							((struct sockaddr *)(&cliaddr))->sa_family,
							ntohs(((struct sockaddr_in *)&cliaddr)->sin_port));
					}
					else if(((struct sockaddr *)&cliaddr)->sa_family == AF_INET6) {
						char dst[INET6_ADDRSTRLEN];
						inet_ntop(((struct sockaddr *)&cliaddr)->sa_family,&(((struct sockaddr_in6 *)&cliaddr)->sin6_addr),dst,INET6_ADDRSTRLEN);
						fprintf(stderr, "Connection from [%s] port %s [%s/%s] accepted (family %d, sport %d)\n",
							dst,
							portlist[i],
							proto,
							sv ? sv->s_name : "*",
							((struct sockaddr *)&cliaddr)->sa_family,
							ntohs(((struct sockaddr_in6 *)&cliaddr)->sin6_port));
					}
					else {
						fprintf(stderr, "Connection from unknown port %s [%s/%s] accepted (family %d, sport %d)\n",
							portlist[i],
							proto,
							sv ? sv->s_name : "*",
							((struct sockaddr *)(&cliaddr))->sa_family,
							ntohs(((struct sockaddr_in *)&cliaddr)->sin_port));
					}
				}
                                if(!kflag) {
                                    /* close listening sockets (in child process, if -m 1+ ) */
                                    int j;
                                    for (j = 0; j < num_destinations; ++j)
                                        close(listen_poll[j].fd);
                                }
				connect_stdin_stdout_to(connfd, i, endpoint2host, endpoint2port, hints, proxyhost, proxyport, proxyhints, socksv, Pflag, headers);
				readwrite(connfd);
				shutdown_endpoint2(endpoint2host);
				close(connfd);
			}

			if (vflag && kflag)
                                fprintf(stderr, "Connection closed, listening again.\n");
			if (kflag)
				continue;
			if (family != AF_UNIX) {
				close(s);
			}
			else if (uflag) {
				if (connect(s, NULL, 0) < 0)
					err(1, "connect");
			}
			exit(0);
		    }
		  }
		}
	} else if (family == AF_UNIX) {
		int i = -1;
		for (;;) {
			if (++i >= num_destinations)
				i = 0;

			if (handle_mflag()) {
				if (vflag)
					fprintf(stderr, "Forked child process to handle connection to %s.\n", hostlist[i]);
				continue;
			}
			ret = 0;

			if ((s = unix_connect(hostlist[i])) > 0 && !zflag) {
				connect_stdin_stdout_to(s, i, endpoint2host, endpoint2port, hints, proxyhost, proxyport, proxyhints, socksv, Pflag, headers);
				readwrite(s);
				shutdown_endpoint2(endpoint2host);
				close(s);
			} else
				ret = 1;
		
			if ((!kflag && i+1 == num_destinations) || ret)
				break;

			if (vflag)
				fprintf(stderr, "Connection closed, opening next connection.\n");
		}	
		if (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);
	} else {
		int i;

		/* Cycle through portlist, connecting to each port. */
		for (i = 0; kflag || i < num_destinations; i++) {
			if (i >= num_destinations)
				i = 0;
			
			if (s)
				close(s);

			if (handle_mflag()) {
				if (vflag)
					fprintf(stderr, "Forked child process to handle connection to %s:%s.\n", hostlist[i], portlist[i]);
				continue;
			}
			
			s = recursive_connect(hostlist[i], portlist[i], hints,
			    proxyhost, proxyport, proxyhints, socksv,
			    Pflag, headers);

			if (s < 0)
				continue;

			ret = 0;
			if (vflag) {
				/* For UDP, make sure we are connected. */
				if (uflag) {
					if (udptest(s) == -1) {
						ret = 1;
						continue;
					}
				}

				char *proto = proto_name(uflag, dccpflag);
				/* Don't look up port if -n. */
				if (nflag)
					sv = NULL;
				else {
					sv = getservbyport(
					    ntohs(atoi(portlist[i])),
					    proto);
				}

				fprintf(stderr,
				    "Connection to %s port %s [%s/%s] "
				    "succeeded!\n", hostlist[i], portlist[i],
				    proto,
				    sv ? sv->s_name : "*");
			}
			if (!zflag)
				connect_stdin_stdout_to(s, i, endpoint2host, endpoint2port, hints, proxyhost, proxyport, proxyhints, socksv, Pflag, headers);
				readwrite(s);
				shutdown_endpoint2(endpoint2host);
		}
	}

	if (s)
		close(s);

	exit(ret);
}

/*
 * unix_bind()
 * Returns a unix socket bound to the given path
 */
int
unix_bind(char *path)
{
	struct sockaddr_un sun;
	int s;

	/* Create unix domain socket. */
	if ((s = socket(AF_UNIX, uflag ? SOCK_DGRAM : SOCK_STREAM,
	     0)) < 0)
		return (-1);

	memset(&sun, 0, sizeof(struct sockaddr_un));
	sun.sun_family = AF_UNIX;

	if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
		return (-1);
	}

        unlink(path);

	if (bind(s, (struct sockaddr *)&sun, SUN_LEN(&sun)) < 0) {
		close(s);
		return (-1);
	}
	return (s);
}

/*
 * unix_connect()
 * Returns a socket connected to a local unix socket. Returns -1 on failure.
 */
int
unix_connect(char *path)
{
	struct sockaddr_un sun;
	int s;

	if (uflag) {
		if ((s = unix_bind(unix_dg_tmp_socket)) < 0)
			return (-1);
	} else {
		if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
                        errx(1,"create unix socket failed");
			return (-1);
                }
	}
	(void)fcntl(s, F_SETFD, 1);

	memset(&sun, 0, sizeof(struct sockaddr_un));
	sun.sun_family = AF_UNIX;

	if (strlcpy(sun.sun_path, path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path)) {
		close(s);
		errno = ENAMETOOLONG;
                warn("unix connect abandoned");
		return (-1);
	}
	if (connect(s, (struct sockaddr *)&sun, SUN_LEN(&sun)) < 0) {
                warn("unix connect failed");
		close(s);
		return (-1);
	}
	return (s);

}

/*
 * unix_listen()
 * Create a unix domain socket, and listen on it.
 */
int
unix_listen(char *path)
{
	int s;
	if ((s = unix_bind(path)) < 0)
		return (-1);

	if (listen(s, LISTEN_BACKLOG) < 0) {
		close(s);
		return (-1);
	}
	return (s);
}

const char    *af_name(short af) {
	switch (af) {
	case AF_INET: return "AF_INET";
	case AF_INET6: return "AF_INET6";
	default: return "AF_UNKNOWN";
	}
}

char *proto_name(int uflag, int dccpflag) {

    char *proto = NULL;
    if (uflag) {
	proto = "udp";
    }
# if defined(IPPROTO_DCCP) && defined(SOCK_DCCP)
    else if (dccpflag) {
	proto = "dccp";
    }
# endif
    else {
	proto = "tcp";
    }

    return proto;
}

/*
 * remote_connect()
 * Returns a socket connected to a remote host. Properly binds to a local
 * port or source address if needed. Returns -1 on failure.
 */
int
remote_connect(const char *host, const char *port, struct addrinfo hints)
{
	struct addrinfo *res, *res0;
	int s, error, on = 1;

	if ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	do {
		if ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			continue;

# if defined(RT_TABLEID_MAX)
		if (rtableid) {
			if (setsockopt(s, SOL_SOCKET, SO_RTABLE, &rtableid,
			    sizeof(rtableid)) == -1)
				err(1, "setsockopt SO_RTABLE");
		}
# endif

		/* Bind to a local port or source address if specified. */
		if (sflag || pflag) {
			struct addrinfo ahints, *ares;

# if defined (SO_BINDANY)
			/* try SO_BINDANY, but don't insist */
			setsockopt(s, SOL_SOCKET, SO_BINDANY, &on, sizeof(on));
# endif
			memset(&ahints, 0, sizeof(struct addrinfo));
			ahints.ai_family = res0->ai_family;
			if (uflag) {
			    ahints.ai_socktype = SOCK_DGRAM;
			    ahints.ai_protocol = IPPROTO_UDP;

			}
# if defined(IPPROTO_DCCP) && defined(SOCK_DCCP)
			else if (dccpflag) {
			    hints.ai_socktype = SOCK_DCCP;
			    hints.ai_protocol = IPPROTO_DCCP;
			}
# endif
			else {
		    	    ahints.ai_socktype = SOCK_STREAM;
			    ahints.ai_protocol = IPPROTO_TCP;
			}
			ahints.ai_flags = AI_PASSIVE;
			if ((error = getaddrinfo(sflag, pflag, &ahints, &ares)))
				errx(1, "getaddrinfo: %s", gai_strerror(error));

			if (bind(s, (struct sockaddr *)ares->ai_addr,
			    ares->ai_addrlen) < 0)
				errx(1, "bind failed: %s", strerror(errno));
			freeaddrinfo(ares);
		}

		set_common_sockopts(s);
		char *proto = proto_name(uflag, dccpflag);
		const char *af = "";
		if (res0->ai_addrlen > sizeof(short))
			af = af_name(*(short*)res0->ai_addr);

                if ((error = connect_with_timeout(s, res0->ai_addr, res0->ai_addrlen, timeout))== CONNECTION_SUCCESS) {
			if (vflag)
				warnx("connect to %s port %s (%s/%s) succeeded", host, port, proto, af);
			break;
		}
		else if (vflag && error == CONNECTION_FAILED) {
			warn("connect to %s port %s (%s/%s) failed", host, port,
			     proto, af);
		}
                else if (vflag && error == CONNECTION_TIMEOUT) {
                    warn("connect to %s port %s (%s/%s) timed out", host, port,
                             proto, af);
		}

		close(s);
		s = -1;
	} while ((res0 = res0->ai_next) != NULL);

	freeaddrinfo(res);

	return (s);
}

static int connect_with_timeout(int fd, const struct sockaddr *sa,
		                socklen_t salen, int ctimeout)
{
	int err;
	struct timeval tv, *tvp = NULL;
	fd_set connect_fdset;
	socklen_t len;
	int orig_flags;

	orig_flags = fcntl(fd, F_GETFL, 0);
	if (fcntl(fd, F_SETFL, orig_flags | O_NONBLOCK) < 0 ) {
		warn("can't set O_NONBLOCK - timeout not available");
		if (connect(fd, sa, salen) == 0)
			return CONNECTION_SUCCESS;
		else
			return CONNECTION_FAILED;
	}

	/* set connect timeout */
	if (ctimeout > 0) {
		tv.tv_sec = (time_t)ctimeout/1000;
		tv.tv_usec = 0;
		tvp = &tv;
	}

	/* attempt the connection */
	err = connect(fd, sa, salen);
	if (err != 0 && errno == EINPROGRESS) {
		/* connection is proceeding
		 * it is complete (or failed) when select returns */

		/* initialize connect_fdset */
		FD_ZERO(&connect_fdset);
		FD_SET(fd, &connect_fdset);

		/* call select */
		do {
			err = select(fd + 1, NULL, &connect_fdset,
				     NULL, tvp);
		} while (err < 0 && errno == EINTR);

		/* select error */
		if (err < 0)
			errx(1,"select error: %s", strerror(errno));
		/* we have reached a timeout */
		if (err == 0)
			return CONNECTION_TIMEOUT;
		/* select returned successfully, but we must test socket
		 * error for result */
		len = sizeof(err);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
			errx(1, "getsockopt error: %s", strerror(errno));
		/* setup errno according to the result returned by
		 * getsockopt */
		if (err != 0)
			errno = err;
	}

	/* return aborted if an error occured, and valid otherwise */
	fcntl(fd, F_SETFL, orig_flags);
	return (err != 0)? CONNECTION_FAILED : CONNECTION_SUCCESS;
}

struct broker_dat {
	int pair_idx;
	int connection_socket;
	int control_socket;
	char pair_id[256];
};

/* for -2 zip and -2 match */
static void connection_broker()
{
	int sv[2];
	pid_t pid;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct broker_dat *bdat1;
	struct broker_dat *bdat2;
	struct broker_dat *bdatlist;
	ssize_t sz;
	char buf1[2048];
	char buf2[2048];
	char YOU_DO_THE_READWRITE = 1;
	char YOU_EXIT = 0;
	struct iovec iov;

	if ((bdatlist = calloc(mflag, sizeof(struct broker_dat))) == NULL)
		err(1, "could not allocate broker data list");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		err(1, "could not create connection broker sockets");

	pid = fork();
	if (pid < 0)
		err(1, "could not fork connection broker");

	if (pid > 0) { /* parent */
		close(sv[0]);
		broker_socket = sv[1];
		shutdown(broker_socket, SHUT_RD);
		return;
	}

	/* child = the broker process */
	close(sv[1]);
	broker_socket = sv[0];
	shutdown(broker_socket, SHUT_WR);

	for(;;) {
		memset(&msg, 0, sizeof(msg));
		msg.msg_control = buf1;
		msg.msg_controllen = sizeof(buf1);
		iov.iov_base = buf2;
		iov.iov_len = sizeof(buf2);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		sz = recvmsg(broker_socket, &msg, 0);
		if (sz < 0) {
			if (errno == EINTR)
				continue;
			err(1, "error on connection broker socket");
		}

		if (sz == 0)
			break;

		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(2*sizeof(int)))
			errx(1, "internal error (cmsg)");

		bdat1 = (struct broker_dat*)buf2;
		bdat1->connection_socket = ((int*)CMSG_DATA(cmsg))[0];
		bdat1->control_socket = ((int*)CMSG_DATA(cmsg))[1];

		for (bdat2 = bdatlist; bdat2->pair_id[0] != 0; ++bdat2) {
			if (strcmp(bdat1->pair_id, bdat2->pair_id) == 0 &&
			(bdat1->pair_idx ^ bdat2->pair_idx) == 1)
				break;
		}

		if (bdat2->pair_id[0] == 0) { /* end of list reached without match */
			if (vflag)
				fprintf(stderr, "Waiting for peer for connection pair \"%s\"\n", bdat1->pair_id);
			memcpy(bdat2, bdat1, sizeof(struct broker_dat));
			continue;
		}

		/* we have a match => unqueue it and marry the pair */
		if (vflag)
			fprintf(stderr, "Connection pair \"%s\" established\n", bdat1->pair_id);

		if (pipe(sv) < 0)
			err(1, "pipe");

		memset(&msg, 0, sizeof(msg));
		msg.msg_control = buf1;
		msg.msg_controllen = sizeof(buf1); /* cmsg(2) says this is not redundant */
		iov.iov_base = &YOU_DO_THE_READWRITE;
		iov.iov_len = sizeof(YOU_DO_THE_READWRITE);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(2*sizeof(int));
		((int*)CMSG_DATA(cmsg))[0] = bdat1->connection_socket;
		((int*)CMSG_DATA(cmsg))[1] = sv[0]; /* read end of the pipe */
		msg.msg_controllen = CMSG_SPACE(2*sizeof(int));
		if (sendmsg(bdat2->control_socket, &msg, 0) < 0)
			err(1, "sendmsg");

		iov.iov_base = &YOU_EXIT;
		iov.iov_len = sizeof(YOU_EXIT);
		((int*)CMSG_DATA(cmsg))[0] = bdat2->connection_socket;
		((int*)CMSG_DATA(cmsg))[1] = sv[1]; /* write end of the pipe */
		if (sendmsg(bdat1->control_socket, &msg, 0) < 0)
			err(1, "sendmsg");

		close(bdat1->control_socket);
		close(bdat2->control_socket);
		close(bdat1->connection_socket);
		close(bdat2->connection_socket);
		close(sv[0]);
		close(sv[1]);

		/* find last entry in bdatlist */
		for (bdat1 = bdat2; bdat1->pair_id[0] != 0; ++bdat1);
		--bdat1;
		/* move last entry to place of bdat2 and 0 out the last entry */
		memmove(bdat2, bdat1, sizeof(struct broker_dat));
		memset(bdat1, 0, sizeof(struct broker_dat));
	}

	exit(0); /* connection broker process does not return */
}

static int pair_socket(int request_sock, int destination_idx, const char* endpoint2host, const char* endpoint2port, int *pipe_fd)
{
	int sv[2];
	size_t len = 1; /* 1 for the 0 terminator */
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct broker_dat bdat;
	char buf[32];
	struct iovec iov;
	char what_to_do;
	ssize_t sz;

	if (endpoint2host != NULL)
		len += strlen(endpoint2host);
	if (endpoint2port != NULL)
		len += 1+strlen(endpoint2port); /* +1 for ":" */

	if (len > sizeof(bdat.pair_id))
		errx(1, "pair connection id longer than %d: \"%s:%s\"", (int)sizeof(bdat.pair_id), endpoint2host, endpoint2port);

	bdat.pair_id[0] = 0;
	if (endpoint2host != NULL)
		strcat(bdat.pair_id, endpoint2host);
	if (endpoint2port != NULL) {
		strcat(bdat.pair_id, ":");
		strcat(bdat.pair_id, endpoint2port);
	}

	/* create sockets for communicating with broker */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		err(1, "could not create sockets for communicating with connection broker");

	bdat.pair_idx = destination_idx;
	bdat.connection_socket = request_sock;
	bdat.control_socket = sv[1];

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf); /* cmsg(2) says this is not redundant */
	iov.iov_base = &bdat;
	iov.iov_len = sizeof(struct broker_dat);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(2*sizeof(int));
	((int*)CMSG_DATA(cmsg))[0] = bdat.connection_socket;
	((int*)CMSG_DATA(cmsg))[1] = bdat.control_socket;
	msg.msg_controllen = CMSG_SPACE(2*sizeof(int));
	if (sendmsg(broker_socket, &msg, 0) < 0)
		err(1, "sendmsg");

	close(sv[1]);

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);
	iov.iov_base = &what_to_do;
	iov.iov_len = sizeof(what_to_do);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	sz = recvmsg(sv[0], &msg, 0);
	if (sz <= 0)
		err(1, "error on connection broker socket");

	close(sv[0]);

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(2*sizeof(int)))
		errx(1, "internal error (cmsg)");

	if (what_to_do == 0) {
		*pipe_fd = -1;
		/* leave file descriptor ((int*)CMSG_DATA(cmsg))[1] open! */
		return ((int*)CMSG_DATA(cmsg))[0];
	} else {
		*pipe_fd = ((int*)CMSG_DATA(cmsg))[1];
		return ((int*)CMSG_DATA(cmsg))[0];
	}
}

static void connect_stdin_stdout_to(int request_sock, int destination_idx, const char *endpoint2host, const char *endpoint2port,
	struct addrinfo hints, const char *proxyhost[], const char *proxyport[],
	struct addrinfo proxyhints, int socksv, const char *proxyuser, char *headers)
{
	int s;
	int proxy_proto;
	int is_match = (endpoint2host == MATCH);
	int is_proxy = (endpoint2host == PROXY) || is_match;
	int is_zip   = (endpoint2host == ZIP);
	int pipe_fd;
	char buf[1];

	if (endpoint2host == NULL)
		return;

	if (is_proxy)
		proxy_proto = proxy_read_connection_request(request_sock, (char**)&endpoint2host, (char**)&endpoint2port);

	if (is_match || is_zip) {
		/* pair_socket() sends the request_sock file descriptor
		over a UDS socket to the connection_broker() process. When that process
		has received a suitable partner from another process
		it will return the partner file descriptor.
		2 connections can be paired if they have the same
		endpoint2host+endpoint2port and if their destination_idx
		values differ in bit 0 but are otherwise identical.
		In the process that should execute the readwrite()
		the read end of a pipe is returned in pipe_fd. The
		process that should terminate after signalling success
		to its proxy client gets pipe_fd < 0 returned and will
		have the write end of the pipe open in its process.
		When the process terminates this write end will automatically
		close which is the signal to the other process to start with the
		readwrite(). */
		s = pair_socket(request_sock, destination_idx, endpoint2host, endpoint2port, &pipe_fd);
		close(broker_socket);
	} else
		s = recursive_connect(endpoint2host, endpoint2port, hints,
		proxyhost, proxyport, proxyhints, socksv,
		proxyuser, headers);

	if (s < 0) {
		if (is_proxy)
			proxy_send_error_reply(request_sock, proxy_proto);
		errx(1, "could not connect to 2nd endpoint");
	}

	if ((dup2(s, fileno(stdin)) < 0) || (dup2(s, fileno(stdout)) < 0)) {
		if (is_proxy)
			proxy_send_error_reply(request_sock, proxy_proto);
		err(1, "could not set stdin+stdout to 2nd endpoint");
	}

	if (is_proxy) {
		proxy_send_success_reply(request_sock, proxy_proto, s);
		free((void*)endpoint2host);
		free((void*)endpoint2port);
	}

	close(s);

	if (is_match || is_zip) {
		if (pipe_fd < 0)
			exit(0); /* closes the write end of the pipe, so other side's read() returns */
		else
			read(pipe_fd, buf, 1); /* wait till other process exits */

		close(pipe_fd);
	}
}

static void shutdown_endpoint2(const char *endpoint2host) {
	if (endpoint2host == NULL)
		return;

	/* Do NOT use close() here because it would free
	the file descriptors for re-use and they would end up
	being used for the next primary connection which would
	cause everything to break horribly. */
	shutdown(fileno(stdin),  SHUT_RDWR);
	shutdown(fileno(stdout), SHUT_RDWR);
}

/*
 * local_listen()
 * Returns a socket listening on a local port, binds to specified source
 * address. Returns -1 on failure.
 */
int
local_listen(char *host, char *port, struct addrinfo hints)
{
	struct addrinfo *res, *res0;
	int s, ret, x = 1;
	int error;

	/* Allow nodename to be null. */
	hints.ai_flags |= AI_PASSIVE;

	/*
	 * In the case of binding to a wildcard address
	 * default to binding to an ipv4 address.
	 */
	if (host == NULL && hints.ai_family == AF_UNSPEC)
		hints.ai_family = AF_INET;

	if ((error = getaddrinfo(host, port, &hints, &res)))
		errx(1, "getaddrinfo: %s", gai_strerror(error));

	res0 = res;
	do {
		if ((s = socket(res0->ai_family, res0->ai_socktype,
		    res0->ai_protocol)) < 0)
			continue;

# if defined(RT_TABLEID_MAX)
		if (rtableid) {
			if (setsockopt(s, IPPROTO_IP, SO_RTABLE, &rtableid,
			    sizeof(rtableid)) == -1)
				err(1, "setsockopt SO_RTABLE");
		}
# endif

		ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &x, sizeof(x));
		if (ret == -1)
			err(1, NULL);

# if defined(SO_REUSEPORT)
		ret = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &x, sizeof(x));
		if (ret == -1)
			err(1, NULL);
# endif

		set_common_sockopts(s);

		if (bind(s, (struct sockaddr *)res0->ai_addr,
		    res0->ai_addrlen) == 0)
			break;

		close(s);
		s = -1;
	} while ((res0 = res0->ai_next) != NULL);

	if (!uflag && s != -1) {
		if (listen(s, LISTEN_BACKLOG) < 0)
			err(1, "listen");
	}

	freeaddrinfo(res);

	return (s);
}

/*
 * readwrite()
 * Loop that polls on the network file descriptor and stdin.
 */
void
readwrite(int nfd)
{
	struct pollfd pfd[2];
	unsigned char buf[16384];
	int n, wfd = fileno(stdin);
	int lfd = fileno(stdout);
	int plen;

	plen = jflag ? 16384 : 2048;

	/* Setup Network FD */
	pfd[0].fd = nfd;
	pfd[0].events = POLLIN;

	/* Set up STDIN FD. */
	pfd[1].fd = wfd;
	pfd[1].events = POLLIN;

	while (pfd[0].fd != -1) {
		if (iflag)
			sleep(iflag);

		if ((n = poll(pfd, 2 - dflag, timeout)) < 0) {
			close(nfd);
			err(1, "Polling Error");
		}

		if (n == 0)
			return;

		if (pfd[0].revents & POLLIN) {
			if ((n = read(nfd, buf, plen)) < 0)
				return;
			else if (n == 0) {
				goto shutdown_rd;
			} else {
				if (tflag)
					atelnet(nfd, buf, n);
				if (atomicio(vwrite, lfd, buf, n) != n)
					return;
			}
		}
		else if (pfd[0].revents & POLLHUP) {
		shutdown_rd:
			shutdown(nfd, SHUT_RD);
			pfd[0].fd = -1;
			pfd[0].events = 0;
		}

		if (!dflag) {
		    if(pfd[1].revents & POLLIN) {
			if ((n = read(wfd, buf, plen)) < 0)
				return;
			else if (n == 0) {
				goto shutdown_wr;
			} else {
				if ((Cflag) && (buf[n-1]=='\n')) {
					if (atomicio(vwrite, nfd, buf, n-1) != (n-1))
						return;
					if (atomicio(vwrite, nfd, "\r\n", 2) != 2)
						return;
				}
				else {
					if (atomicio(vwrite, nfd, buf, n) != n)
						return;
				}
			}
			}
			else if (pfd[1].revents & POLLHUP) {
			shutdown_wr:
			shutdown(nfd, SHUT_WR);
			if (!qflag)
				return;
			/* if the user asked to exit on EOF, do it */
			if (qtime == 0)
				quit();
			/* if user asked to die after a while, arrange for it */
			if (qtime > 0) {
				signal(SIGALRM, quit);
				alarm(qtime);
			}
			pfd[1].fd = -1;
			pfd[1].events = 0;
			}
		}
	}
}

/* Deal with RFC 854 WILL/WONT DO/DONT negotiation. */
void
atelnet(int nfd, unsigned char *buf, unsigned int size)
{
	unsigned char *p, *end;
	unsigned char obuf[4];

	if (size < 3)
		return;
	end = buf + size - 2;

	for (p = buf; p < end; p++) {
		if (*p != IAC)
			continue;

		obuf[0] = IAC;
		p++;
		if ((*p == WILL) || (*p == WONT))
			obuf[1] = DONT;
		else if ((*p == DO) || (*p == DONT))
			obuf[1] = WONT;
		else
			continue;

		p++;
		obuf[2] = *p;
		if (atomicio(vwrite, nfd, obuf, 3) != 3)
			warn("Write Error!");
	}
}

void
expand_portrange(char* host, char* p)
{
	struct servent *sv;
	const char *errstr;
	char *n;
	int hi, lo, cp;

	char *proto = proto_name(uflag, dccpflag);
	sv = getservbyname(p, proto);
        if (sv) {
                portlist[num_destinations] = calloc(1, PORT_MAX_LEN);
                if (portlist[num_destinations] == NULL)
			err(1, "calloc");
                snprintf(portlist[num_destinations], PORT_MAX_LEN, "%d", ntohs(sv->s_port));
                hostlist[num_destinations++] = host;
        } else if ((n = strchr(p, '-')) != NULL) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		if (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(p, 1, PORT_MAX, &errstr);
		if (errstr)
			errx(1, "port number %s: %s", errstr, p);

		if (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		for (cp = lo; cp <= hi; cp++) {
			portlist[num_destinations] = calloc(1, PORT_MAX_LEN);
			if (portlist[num_destinations] == NULL)
				err(1, "calloc");
			snprintf(portlist[num_destinations], PORT_MAX_LEN, "%d", cp);
			hostlist[num_destinations++] = host;
		}
	} else {
		hi = strtonum(p, 1, PORT_MAX, &errstr);
		if (errstr)
			errx(1, "port number %s: %s", errstr, p);
		portlist[num_destinations] = p;
		hostlist[num_destinations++] = host;
	}
}

/*
 * build_ports_and_hosts()
 * Builds arrays of hosts and corresponding ports in hostlist[] and portlist[],
 * listing each port that we should connect to or listen on.
 */
void
build_hosts_and_ports(int argc, char *argv[])
{
	int i;

	memset(portlist, 0, sizeof(portlist));
	memset(hostlist, 0, sizeof(hostlist));

	if (argc > PORT_MAX)
		errx(1, "too many arguments");

	if (argc == 0)
		errx(1, "missing destination");

	if (family == AF_UNIX) {
		memcpy(hostlist, argv, argc * sizeof(char*));
		num_destinations = argc;
		return;
	}

	if (lflag) {
		for (i = 0; i < argc; ++i) {
			if (i == argc-1 || (isdigit(argv[i][0]) && (strchr(argv[i],'.') == NULL))) {
				expand_portrange(NULL, argv[i]);
			} else {
				char* host = argv[i++];
				expand_portrange(host, argv[i]);
			}
		}
	} else {
		if ((argc & 1) != 0)
			errx(1, "missing port for destination %s", argv[argc-1]);

		for (i = 0; i < argc; i+=2)
			expand_portrange(argv[i], argv[i+1]);
	}

	/* Randomly swap ports. */
	if (rflag) {
		int y;
		int x;
		char *c;

		for (x = 0; x < num_destinations; x++) {
			y = arc4random_uniform(num_destinations);
			c = portlist[x];
			portlist[x] = portlist[y];
			portlist[y] = c;
			c = hostlist[x];
			hostlist[x] = hostlist[y];
			hostlist[y] = c;
		}
	}
}

/*
 * udptest()
 * Do a few writes to see if the UDP port is there.
 * Fails once PF state table is full.
 */
int
udptest(int s)
{
	int i, t;

	if ((write(s, "X", 1) != 1) ||
	    ((write(s, "X", 1) != 1) && (errno == ECONNREFUSED)))
		return -1;

	/* Give the remote host some time to reply. */
	for (i = 0, t = (timeout == -1) ? UDP_SCAN_TIMEOUT : (timeout / 1000);
	     i < t; i++) {
		sleep(1);
		if ((write(s, "X", 1) != 1) && (errno == ECONNREFUSED))
			return -1;
	}
	return 1;
}

void
set_common_sockopts(int s)
{
	int x = 1;

# if defined(SO_BROADCAST)
	if (bflag) {
		if (setsockopt(s, IPPROTO_TCP, SO_BROADCAST,
			&x, sizeof(x)) == -1)
			err(1, NULL);
	}
# endif
# if defined(TCP_MD5SIG)
	if (Sflag) {
		if (setsockopt(s, IPPROTO_TCP, TCP_MD5SIG,
			&x, sizeof(x)) == -1)
			err(1, NULL);
	}
# endif
	if (Dflag) {
		if (setsockopt(s, SOL_SOCKET, SO_DEBUG,
			&x, sizeof(x)) == -1)
			err(1, NULL);
	}
# if defined(SO_JUMBO)
	if (jflag) {
		if (setsockopt(s, SOL_SOCKET, SO_JUMBO,
			&x, sizeof(x)) == -1)
			err(1, NULL);
	}
# endif
	if (Tflag != -1) {
		if (setsockopt(s, IPPROTO_IP, IP_TOS,
		    &Tflag, sizeof(Tflag)) == -1)
			err(1, "set IP ToS");
	}
	if (Iflag) {
		if (setsockopt(s, SOL_SOCKET, SO_RCVBUF,
		    &Iflag, sizeof(Iflag)) == -1)
			err(1, "set TCP receive buffer size");
	}
	if (Oflag) {
		if (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
		    &Oflag, sizeof(Oflag)) == -1)
			err(1, "set TCP send buffer size");
	}
}

int
map_tos(char *s, int *val)
{
	/* DiffServ Codepoints and other TOS mappings */
	const struct toskeywords {
		const char	*keyword;
		int		 val;
	} *t, toskeywords[] = {
		{ "af11",		IPTOS_DSCP_AF11 },
		{ "af12",		IPTOS_DSCP_AF12 },
		{ "af13",		IPTOS_DSCP_AF13 },
		{ "af21",		IPTOS_DSCP_AF21 },
		{ "af22",		IPTOS_DSCP_AF22 },
		{ "af23",		IPTOS_DSCP_AF23 },
		{ "af31",		IPTOS_DSCP_AF31 },
		{ "af32",		IPTOS_DSCP_AF32 },
		{ "af33",		IPTOS_DSCP_AF33 },
		{ "af41",		IPTOS_DSCP_AF41 },
		{ "af42",		IPTOS_DSCP_AF42 },
		{ "af43",		IPTOS_DSCP_AF43 },
		{ "critical",		IPTOS_PREC_CRITIC_ECP },
		{ "cs0",		IPTOS_DSCP_CS0 },
		{ "cs1",		IPTOS_DSCP_CS1 },
		{ "cs2",		IPTOS_DSCP_CS2 },
		{ "cs3",		IPTOS_DSCP_CS3 },
		{ "cs4",		IPTOS_DSCP_CS4 },
		{ "cs5",		IPTOS_DSCP_CS5 },
		{ "cs6",		IPTOS_DSCP_CS6 },
		{ "cs7",		IPTOS_DSCP_CS7 },
		{ "ef",			IPTOS_DSCP_EF },
		{ "inetcontrol",	IPTOS_PREC_INTERNETCONTROL },
		{ "lowcost",		IPTOS_LOWCOST },
		{ "lowdelay",		IPTOS_LOWDELAY },
		{ "netcontrol",		IPTOS_PREC_NETCONTROL },
		{ "reliability",	IPTOS_RELIABILITY },
		{ "throughput",		IPTOS_THROUGHPUT },
		{ NULL, 		-1 },
	};

	for (t = toskeywords; t->keyword != NULL; t++) {
		if (strcmp(s, t->keyword) == 0) {
			*val = t->val;
			return (1);
		}
	}

	return (0);
}

void
help(void)
{
# if defined(DEBIAN_VERSION)
        fprintf(stderr, "OpenBSD netcat (Debian patchlevel " DEBIAN_VERSION ")\n");
# endif
	usage(0);
	fprintf(stderr, "\tCommand Summary:\n\
	\t-2 endpoint2	Connect to endpoint2 and use instead of stdin/out\n\
	\t-4		Use IPv4\n\
	\t-6		Use IPv6\n\
	\t-b		Allow broadcast\n\
	\t-C		Send CRLF as line-ending\n\
	\t-D		Enable the debug socket option\n\
	\t-d		Detach from stdin\n\
	\t-h		This help text\n\
	\t-H header:value\tAdd HTTP header when CONNECTing to proxy\n\
	\t-I length	TCP receive buffer length\n\
	\t-i secs\t	Delay interval for lines sent, ports scanned\n\
	\t-j		Use jumbo frame\n\
	\t-k		Keep re-connecting/listening after connections close\n\
	\t-l		Listen mode, for inbound connects\n\
	\t-m maxfork	Handle up to maxfork connections in parallel\n\
	\t-n		Suppress name/port resolutions\n\
	\t-O length	TCP send buffer length\n\
	\t-P proxyuser\tUsername for proxy authentication\n\
	\t-p port\t	Specify local port for remote connects\n\
        \t-q secs\t	quit after EOF on stdin and delay of secs\n\
	\t-r		Randomize remote ports\n\
	\t-S		Enable the TCP MD5 signature option\n\
	\t-s addr\t	Local source address\n\
	\t-T toskeyword\tSet IP Type of Service\n\
	\t-t		Answer TELNET negotiation\n\
	\t-U		Use UNIX domain socket\n\
	\t-u		UDP mode\n\
	\t-V rtable	Specify alternate routing table\n\
	\t-v		Verbose\n\
	\t-w secs\t	Timeout for connects and final net reads\n\
	\t-X proto	Proxy protocol: \"4\", \"5\" (SOCKS) or \"connect\"\n\
	\t-x addr[:port]\tSpecify proxy address and port\n\
	\t-Z		DCCP mode\n\
	\t-z		Zero-I/O mode [used for scanning]\n\
	Port numbers can be individual or ranges: lo-hi [inclusive]\n");
	exit(0);
}

void
usage(int ret)
{
	fprintf(stderr,
	    "usage: nc [-46bCDdhjklnrStUuvZz] [-I length] [-2 endpoint2] [-i interval]\n"
	    "\t  [-H header:value] [-m maxfork] [-O length] [-P proxy_username] [-p source_port]\n"
	    "\t  [-q seconds] [-s source] [-T toskeyword] [-V rtable] [-w timeout]\n"
	    "\t  [-X proxy_protocol] [-x proxy_address[:port]] [destination] [port]\n"
	    "\t  [destination2...]\n");
	if (ret)
		exit(1);
}

/*
 * quit()
 * handler for a "-q" timeout (exit 0 instead of 1)
 */
static void quit()
{
        /* XXX: should explicitly close fds here */
        exit(0);
}
