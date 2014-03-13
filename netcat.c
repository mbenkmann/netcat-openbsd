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

#define CONNECTION_SUCCESS 0
#define CONNECTION_FAILED 1
#define CONNECTION_TIMEOUT 2

#define UDP_SCAN_TIMEOUT 3			/* Seconds */

#define LISTEN_BACKLOG 5

char *PROXY = "proxy";

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
char *unix_dg_tmp_socket;

void	atelnet(int, unsigned char *, unsigned int);
void	build_ports(char **);
void	help(void);
int	local_listen(char *, char *, struct addrinfo);
void	readwrite(int);
int	remote_connect(const char *, const char *, struct addrinfo);
int	socks_connect(const char *, const char *, struct addrinfo,
	    const char *, const char *, struct addrinfo, int, const char *, char*);
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
static void connect_stdin_stdout_to(int request_sock, const char *endpoint2host, const char *endpoint2port,
	struct addrinfo hints, const char *proxyhost, const char *proxyport,
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
	char *host, **uport;
	struct addrinfo hints;
	struct servent *sv;
	socklen_t len;
	union {
        	struct sockaddr_storage storage;
		struct sockaddr_un forunix;
	} cliaddr;
	char *proxy = NULL;
	const char *errstr, *proxyhost = "", *proxyport = NULL;
	char *endpoint2 = NULL;
	char *endpoint2host = NULL, *endpoint2port = NULL;
	char* headers = NULL;
	struct addrinfo proxyhints;
	char unix_dg_tmp_socket_buf[UNIX_DG_TMP_SOCKET_SIZE];

	ret = 1;
	s = 0;
	socksv = 5;
	host = NULL;
	uport = NULL;
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
	if (argv[0] && !argv[1] && family == AF_UNIX) {
# if defined(IPPROTO_DCCP) && defined(SOCK_DCCP)
		if (dccpflag)
			errx(1, "cannot use -Z and -U");
# endif
		host = argv[0];
		uport = NULL;
	} else if (argv[0] && !argv[1] && lflag) {
		if (pflag) {
			uport = &pflag;
			host = argv[0];
		} else {
			uport = argv;
			host = NULL;
		}
	} else if (!argv[0] && lflag && pflag) {
		uport = &pflag;
		host = NULL;
	} else if (argv[0] && argv[1]) {
		host = argv[0];
		uport = &argv[1];
	} else
		usage(1);

	if (lflag) {
		if (sflag)
			errx(1, "cannot use -s and -l");
		if (zflag)
			errx(1, "cannot use -z and -l");
		if (pflag)
			/* This still does not work well because of getopt mess
			errx(1, "cannot use -p and -l"); */
			uport = &pflag;
	}
	
	if (mflag && uflag)
            		errx(1, "cannot use -m with -u");

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

		proxyhost = strsep(&proxy, ":");
		proxyport = proxy;

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

		endpoint2port = strrchr(endpoint2, ':');
		endpoint2host = endpoint2;
		if (endpoint2port == NULL) {
			if (endpoint2 != PROXY)
				errx(1, "port missing in -2 address: %s", endpoint2);
		} else
			*endpoint2port++ = 0;
	}

	if (lflag) {
		int connfd;
		ret = 0;

		if (family == AF_UNIX) {
			if (uflag)
				s = unix_bind(host);
			else
				s = unix_listen(host);
		} else
			s = local_listen(host, *uport, hints);
		if (s < 0)
			err(1, NULL);

		char* local;
		if (family == AF_INET6)
			local = ":::";
		else
			local = "0.0.0.0";
		if (vflag && (family != AF_UNIX))
		fprintf(stderr, "Listening on [%s] (family %d, port %s)\n",
			host ?: local,
			family,
			*uport);

		for (;;) {

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
				if (rv < 0)
					err(1, "recvfrom");

				rv = connect(s, (struct sockaddr *)&cliaddr, len);
				if (rv < 0)
					err(1, "connect");

				readwrite(s);
			} else {
				len = sizeof(cliaddr);
				connfd = accept(s, (struct sockaddr *)&cliaddr,
				    &len);
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
						sv = getservbyport(ntohs(atoi(*uport)),
							proto);

					if (((struct sockaddr *)&cliaddr)->sa_family == AF_INET) {
						char dst[INET_ADDRSTRLEN];
						inet_ntop(((struct sockaddr *)&cliaddr)->sa_family,&(((struct sockaddr_in *)&cliaddr)->sin_addr),dst,INET_ADDRSTRLEN);
						fprintf(stderr, "Connection from [%s] port %s [%s/%s] accepted (family %d, sport %d)\n",
							dst,
							*uport,
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
							*uport,
							proto,
							sv ? sv->s_name : "*",
							((struct sockaddr *)&cliaddr)->sa_family,
							ntohs(((struct sockaddr_in6 *)&cliaddr)->sin6_port));
					}
					else {
						fprintf(stderr, "Connection from unknown port %s [%s/%s] accepted (family %d, sport %d)\n",
							*uport,
							proto,
							sv ? sv->s_name : "*",
							((struct sockaddr *)(&cliaddr))->sa_family,
							ntohs(((struct sockaddr_in *)&cliaddr)->sin_port));
					}
				}
                                if(!kflag)
                                        close(s);
				connect_stdin_stdout_to(connfd, endpoint2host, endpoint2port, hints, proxyhost, proxyport, proxyhints, socksv, Pflag, headers);
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
			break;
		}
	} else if (family == AF_UNIX) {
		for (;;) {
			if (handle_mflag()) {
				if (vflag)
					fprintf(stderr, "Forked child process to handle connection to %s.\n", host);
				continue;
			}
			ret = 0;

			if ((s = unix_connect(host)) > 0 && !zflag) {
				connect_stdin_stdout_to(s, endpoint2host, endpoint2port, hints, proxyhost, proxyport, proxyhints, socksv, Pflag, headers);
				readwrite(s);
				shutdown_endpoint2(endpoint2host);
				close(s);
			} else
				ret = 1;
		
			if (!kflag || ret)
				break;

			if (vflag)
				fprintf(stderr, "Connection closed, re-connecting.\n");
		}	
		if (uflag)
			unlink(unix_dg_tmp_socket);
		exit(ret);
	} else {
		int i = 0;

		/* Construct the portlist[] array. */
		build_ports(uport);

		/* Cycle through portlist, connecting to each port. */
		for (i = 0; (portlist[i] != NULL) || ((i > 0) && kflag); i++) {
			if (portlist[i] == NULL)
				i = 0;
			
			if (s)
				close(s);

			if (handle_mflag()) {
				if (vflag)
					fprintf(stderr, "Forked child process to handle connection to %s:%s.\n", host, portlist[i]);
				continue;
			}
			
			if (xflag)
				s = socks_connect(host, portlist[i], hints,
				    proxyhost, proxyport, proxyhints, socksv,
				    Pflag, headers);
			else
				s = remote_connect(host, portlist[i], hints);

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
				    "succeeded!\n", host, portlist[i],
				    proto,
				    sv ? sv->s_name : "*");
			}
			if (!zflag)
				connect_stdin_stdout_to(s, endpoint2host, endpoint2port, hints, proxyhost, proxyport, proxyhints, socksv, Pflag, headers);
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
			warnx("connect to %s port %s (%s/%s) succeeded", host, port,
			     proto, af);  
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

static void connect_stdin_stdout_to(int request_sock, const char *endpoint2host, const char *endpoint2port,
	struct addrinfo hints, const char *proxyhost, const char *proxyport,
	struct addrinfo proxyhints, int socksv, const char *proxyuser, char *headers)
{
	int s;
	int proxy_proto;
	int is_proxy = (endpoint2host == PROXY);

	if (endpoint2host == NULL)
		return;

	if (is_proxy)
		proxy_proto = proxy_read_connection_request(request_sock, (char**)&endpoint2host, (char**)&endpoint2port);

	if (xflag)
		s = socks_connect(endpoint2host, endpoint2port, hints,
		    proxyhost, proxyport, proxyhints, socksv,
		    proxyuser, headers);
	else
		s = remote_connect(endpoint2host, endpoint2port, hints);

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

/*
 * build_ports()
 * Build an array of ports in portlist[], listing each port
 * that we should try to connect to.
 */
void
build_ports(char **p)
{
        struct servent *sv;
	const char *errstr;
	char *n;
	int hi, lo, cp;
	int x = 0;
	int i;

	char *proto = proto_name(uflag, dccpflag);
	sv = getservbyname(*p, proto);
        if (sv) {
                portlist[0] = calloc(1, PORT_MAX_LEN);
                if (portlist[0] == NULL)
                        err(1, NULL);
                snprintf(portlist[0], PORT_MAX_LEN, "%d", ntohs(sv->s_port));
        } else if ((n = strchr(*p, '-')) != NULL) {
		*n = '\0';
		n++;

		/* Make sure the ports are in order: lowest->highest. */
		hi = strtonum(n, 1, PORT_MAX, &errstr);
		if (errstr)
			errx(1, "port number %s: %s", errstr, n);
		lo = strtonum(*p, 1, PORT_MAX, &errstr);
		if (errstr)
			errx(1, "port number %s: %s", errstr, *p);

		if (lo > hi) {
			cp = hi;
			hi = lo;
			lo = cp;
		}

		/* Load ports sequentially. */
		for (cp = lo; cp <= hi; cp++) {
			portlist[x] = calloc(1, PORT_MAX_LEN);
			if (portlist[x] == NULL)
				err(1, NULL);
			snprintf(portlist[x], PORT_MAX_LEN, "%d", cp);
			x++;
		}

		/* Randomly swap ports. */
		if (rflag) {
			int y;
			char *c;

			for (x = 0; x <= (hi - lo); x++) {
				y = (arc4random() & 0xFFFF) % (hi - lo);
				c = portlist[x];
				portlist[x] = portlist[y];
				portlist[y] = c;
			}
		}
	} else {
		hi = strtonum(*p, 1, PORT_MAX, &errstr);
		if (errstr)
			errx(1, "port number %s: %s", errstr, *p);
		for (i=0;p[i];i++) {
			portlist[i] = strdup(p[i]);
		}
		if (portlist[0] == NULL)
			err(1, NULL);
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
	    "\t  [-X proxy_protocol] [-x proxy_address[:port]] [destination] [port]\n");
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
