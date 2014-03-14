/*	$OpenBSD: socks.c,v 1.19 2011/02/12 15:54:18 okan Exp $	*/

/*
 * Copyright (c) 1999 Niklas Hallqvist.  All rights reserved.
 * Copyright (c) 2004, 2005 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <resolv.h>
#include <bsd/readpassphrase.h>
#include "atomicio.h"

#define SOCKS_PORT	"1080"
#define HTTP_PROXY_PORT	"3128"
#define HTTP_MAXHDRS	64
#define SOCKS_V5	5
#define SOCKS_V4	4
#define SOCKS_NOAUTH	0
#define SOCKS_NOMETHOD	0xff
#define SOCKS_CONNECT	1
#define SOCKS_IPV4	1
#define SOCKS_DOMAIN	3
#define SOCKS_IPV6	4

int	remote_connect(const char *, const char *, struct addrinfo);
int	socks_connect(const char *, const char *, struct addrinfo,
	    const char *, const char *, struct addrinfo, int,
	    const char *, char*);
int	proxy_read_connection_request(int request_sock, char **host, char **port);
void	proxy_send_error_reply(int request_sock, int proxy_proto);
void	proxy_send_success_reply(int request_sock, int proxy_proto, int peer_sock);
int	asprintf(char **strp, const char *fmt, ...);

static int
decode_addrport(const char *h, const char *p, struct sockaddr *addr,
    socklen_t addrlen, int v4only, int numeric)
{
	int r;
	struct addrinfo hints, *res;

	bzero(&hints, sizeof(hints));
	hints.ai_family = v4only ? PF_INET : PF_UNSPEC;
	hints.ai_flags = numeric ? AI_NUMERICHOST : 0;
	hints.ai_socktype = SOCK_STREAM;
	r = getaddrinfo(h, p, &hints, &res);
	/* Don't fatal when attempting to convert a numeric address */
	if (r != 0) {
		if (!numeric) {
			errx(1, "getaddrinfo(\"%.64s\", \"%.64s\"): %s", h, p,
			    gai_strerror(r));
		}
		return (-1);
	}
	if (addrlen < res->ai_addrlen) {
		freeaddrinfo(res);
		errx(1, "internal error: addrlen < res->ai_addrlen");
	}
	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return (0);
}

static void
read_or_err(int fd, void *buf, size_t count) {
        size_t cnt = atomicio(read, fd, buf, count);
	if (cnt != count)
                err(1, "read failed (%zu/%zu)", cnt, count);
}

static int
proxy_read_line(int fd, char *buf, size_t bufsz)
{
	size_t off;

	for(off = 0;;) {
		if (off >= bufsz)
			errx(1, "proxy read too long");
		if (atomicio(read, fd, buf + off, 1) != 1)
			err(1, "proxy read");
		/* Skip CR */
		if (buf[off] == '\r')
			continue;
		if (buf[off] == '\n') {
			buf[off] = '\0';
			break;
		}
		off++;
	}
	return (off);
}

static void
proxy_skip_headers(int proxyfd) {
	char buf[1024];
	int r;
	/* Headers continue until we hit an empty line */
	for (r = 0; r < HTTP_MAXHDRS; r++) {
		proxy_read_line(proxyfd, buf, sizeof(buf));
		if (*buf == '\0')
			return;
	}
	errx(1, "Too many proxy headers received");
}

static const char *
getproxypass(const char *proxyuser, const char *proxyhost)
{
	char prompt[512];
	static char pw[256];

	snprintf(prompt, sizeof(prompt), "Proxy password for %s@%s: ",
	   proxyuser, proxyhost);
	if (readpassphrase(prompt, pw, sizeof(pw), RPP_REQUIRE_TTY) == NULL)
		errx(1, "Unable to read proxy passphrase");
	return (pw);
}

int
socks_connect(const char *host, const char *port,
    struct addrinfo hints __attribute__ ((__unused__)),
    const char *proxyhost, const char *proxyport, struct addrinfo proxyhints,
    int socksv, const char *proxyuser, char* headers)
{
	int proxyfd, r, authretry = 0;
	size_t hlen, wlen;
	unsigned char buf[1024];
	size_t cnt;
	struct sockaddr_storage addr;
	struct sockaddr_in *in4 = (struct sockaddr_in *)&addr;
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&addr;
	in_port_t serverport;
	const char *proxypass = NULL;

	if (proxyport == NULL)
		proxyport = (socksv == -1) ? HTTP_PROXY_PORT : SOCKS_PORT;

	/* Abuse API to lookup port */
	if (decode_addrport("0.0.0.0", port, (struct sockaddr *)&addr,
	    sizeof(addr), 1, 1) == -1)
		errx(1, "unknown port \"%.64s\"", port);
	serverport = in4->sin_port;

 again:
	if (authretry++ > 3)
		errx(1, "Too many authentication failures");

	proxyfd = remote_connect(proxyhost, proxyport, proxyhints);

	if (proxyfd < 0)
		return (-1);

	if (socksv == 5) {
		if (decode_addrport(host, port, (struct sockaddr *)&addr,
		    sizeof(addr), 0, 1) == -1)
			addr.ss_family = 0; /* used in switch below */

		/* Version 5, one method: no authentication */
		buf[0] = SOCKS_V5;
		buf[1] = 1;
		buf[2] = SOCKS_NOAUTH;
		cnt = atomicio(vwrite, proxyfd, buf, 3);
		if (cnt != 3)
			err(1, "write failed (%zu/3)", (size_t)cnt);

		cnt = atomicio(read, proxyfd, buf, 2);
		if (cnt != 2)
			err(1, "read failed (%zu/3)", (size_t)cnt);

		if (buf[1] == SOCKS_NOMETHOD)
			errx(1, "authentication method negotiation failed");

		switch (addr.ss_family) {
		case 0:
			/* Version 5, connect: domain name */

			/* Max domain name length is 255 bytes */
			hlen = strlen(host);
			if (hlen > 255)
				errx(1, "host name too long for SOCKS5");
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_DOMAIN;
			buf[4] = hlen;
			memcpy(buf + 5, host, hlen);
			memcpy(buf + 5 + hlen, &serverport, sizeof serverport);
			wlen = 7 + hlen;
			break;
		case AF_INET:
			/* Version 5, connect: IPv4 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV4;
			memcpy(buf + 4, &in4->sin_addr, sizeof in4->sin_addr);
			memcpy(buf + 8, &in4->sin_port, sizeof in4->sin_port);
			wlen = 10;
			break;
		case AF_INET6:
			/* Version 5, connect: IPv6 address */
			buf[0] = SOCKS_V5;
			buf[1] = SOCKS_CONNECT;
			buf[2] = 0;
			buf[3] = SOCKS_IPV6;
			memcpy(buf + 4, &in6->sin6_addr, sizeof in6->sin6_addr);
			memcpy(buf + 20, &in6->sin6_port,
			    sizeof in6->sin6_port);
			wlen = 22;
			break;
		default:
			errx(1, "internal error: silly AF");
		}

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		if (cnt != wlen)
			err(1, "write failed (%zu/%zu)", (size_t)cnt, (size_t)wlen);

		cnt = atomicio(read, proxyfd, buf, 4);
		if (cnt != 4)
			err(1, "read failed (%zu/4)", (size_t)cnt);
		if (buf[1] != 0)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
		switch (buf[3]) {
		case SOCKS_DOMAIN:
			read_or_err(proxyfd, buf+4, 1);
			cnt = (unsigned char)buf[4];
			read_or_err(proxyfd, buf+5, cnt+2);
			break;
		case SOCKS_IPV4:
			cnt = atomicio(read, proxyfd, buf + 4, 6);
			if (cnt != 6)
				err(1, "read failed (%lu/6)", (unsigned long)cnt);
			break;
		case SOCKS_IPV6:
			cnt = atomicio(read, proxyfd, buf + 4, 18);
			if (cnt != 18)
				err(1, "read failed (%lu/18)", (unsigned long)cnt);
			break;
		default:
			errx(1, "connection failed, unsupported address type");
		}
	} else if (socksv == 4) {
		/* This will exit on lookup failure */
		decode_addrport(host, port, (struct sockaddr *)&addr,
		    sizeof(addr), 1, 0);

		/* Version 4 */
		buf[0] = SOCKS_V4;
		buf[1] = SOCKS_CONNECT;	/* connect */
		memcpy(buf + 2, &in4->sin_port, sizeof in4->sin_port);
		memcpy(buf + 4, &in4->sin_addr, sizeof in4->sin_addr);
		buf[8] = 0;	/* empty username */
		wlen = 9;

		cnt = atomicio(vwrite, proxyfd, buf, wlen);
		if (cnt != wlen)
			err(1, "write failed (%zu/%zu)", (size_t)cnt, (size_t)wlen);

		cnt = atomicio(read, proxyfd, buf, 8);
		if (cnt != 8)
			err(1, "read failed (%zu/8)", (size_t)cnt);
		if (buf[1] != 90)
			errx(1, "connection failed, SOCKS error %d", buf[1]);
	} else if (socksv == -1) {
		/* HTTP proxy CONNECT */

		/* Disallow bad chars in hostname */
		if (strcspn(host, "\r\n\t []:") != strlen(host))
			errx(1, "Invalid hostname");

		/* Try to be sane about numeric IPv6 addresses */
		if (strchr(host, ':') != NULL) {
			r = snprintf((char*)buf, sizeof(buf),
			    "CONNECT [%s]:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		} else {
			r = snprintf((char*)buf, sizeof(buf),
			    "CONNECT %s:%d HTTP/1.0\r\n",
			    host, ntohs(serverport));
		}
		if (r == -1 || (size_t)r >= sizeof(buf))
			errx(1, "hostname too long");
		r = strlen((char*)buf);

		cnt = atomicio(vwrite, proxyfd, buf, r);
		if (cnt != r)
			err(1, "write failed (%zu/%d)", (size_t)cnt, (int)r);

		if (authretry > 1) {
			char resp[1024];

			proxypass = getproxypass(proxyuser, proxyhost);
			r = snprintf((char*)buf, sizeof(buf), "%s:%s",
			    proxyuser, proxypass);
			if (r == -1 || (size_t)r >= sizeof(buf) ||
			    b64_ntop(buf, strlen((char*)buf), resp,
			    sizeof(resp)) == -1)
				errx(1, "Proxy username/password too long");
			r = snprintf((char*)buf, sizeof((char*)buf), "Proxy-Authorization: "
			    "Basic %s\r\n", resp);
			if (r == -1 || (size_t)r >= sizeof(buf))
				errx(1, "Proxy auth response too long");
			r = strlen((char*)buf);
			if ((cnt = atomicio(vwrite, proxyfd, buf, r)) != r)
				err(1, "write failed (%zu/%d)", (size_t)cnt, r);
		}

		/* Send additional -H headers, if any */
		if (headers != NULL) {
		        r = strlen(headers);
			if ((cnt = atomicio(vwrite, proxyfd, (void*)headers, r)) != r)
				err(1, "write failed (%zu/%d)", (size_t)cnt, r);
                }

		/* Terminate headers */
		if ((r = atomicio(vwrite, proxyfd, "\r\n", 2)) != 2)
			err(1, "write failed (2/%d)", r);

		/* Read status reply */
		proxy_read_line(proxyfd, (char*)buf, sizeof(buf));
		if (proxyuser != NULL &&
		    strncmp((char*)buf, "HTTP/1.0 407 ", 12) == 0) {
			if (authretry > 1) {
				fprintf(stderr, "Proxy authentication "
				    "failed\n");
			}
			close(proxyfd);
			goto again;
		} else if (strncmp((char*)buf, "HTTP/1.0 200 ", 12) != 0 &&
		    strncmp((char*)buf, "HTTP/1.1 200 ", 12) != 0)
			errx(1, "Proxy error: \"%s\"", buf);

		proxy_skip_headers(proxyfd);

	} else
		errx(1, "Unknown proxy protocol %d", socksv);

	return (proxyfd);
}

int
proxy_read_connection_request(int request_sock, char **hostp, char **portp)
{
	char buf[1024];
	uint16_t p = 0;

	*hostp = NULL;
	*portp = NULL;

	read_or_err(request_sock, buf, 1);

	switch (buf[0]) {
	case SOCKS_V4:
		read_or_err(request_sock, buf+1, 7);
		if (buf[1] == SOCKS_CONNECT) {
			p = ntohs(*(uint16_t*)(buf+2));
			uint32_t ip = ntohl(*(uint32_t*)(buf+4));
			/* skip user name */
			for (buf[8] = 255; buf[8] != 0; read_or_err(request_sock, buf+8, 1));
			if (ip > 0 && ip < 256) { /* SOCKSv4a with destination host as string */
				int off = 8;
				/* read destination string */
				for (;;) {
					if (off >= sizeof(buf))
						errx(1, "Destination string in SOCKSv4a request too long");
					read_or_err(request_sock, buf+off, 1);
					if (buf[off++] == 0)
						break;
				}
				if ((*hostp = strdup(buf+8)) == NULL)
					err(1, "strdup");
				if (**hostp == 0)
					errx(1, "Empty destination in SOCKSv4a request");
			} else { /* SOCKSv4 with numeric IP as destination */
				if (0 >= asprintf(hostp, "%u.%u.%u.%u", (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255 ))
					err(1, "could not convert IP address to string");
			}

			if (0 >= asprintf(portp, "%u", (unsigned)p))
					err(1, "could not convert port to string");

			break;
		}
		errx(1, "Illegal SOCKSv4 request"); /* Do not include untrusted user strings in printout! */
	case SOCKS_V5:
	{
		int auth_method = SOCKS_NOMETHOD;
		int count;
		read_or_err(request_sock, buf+1, 1);
		for (count = buf[1]; count > 0; --count) {
			read_or_err(request_sock, buf+1, 1);
			if (buf[1] == SOCKS_NOAUTH)
				auth_method = SOCKS_NOAUTH;
		}

		buf[1] = auth_method;
		if (2 != atomicio(vwrite, request_sock, buf, 2))
			err(1, "write failed");

		if (auth_method == SOCKS_NOMETHOD)
			errx(1, "SOCKSv5 request with no compatible authentication method");

		read_or_err(request_sock, buf, 4);
		if (buf[0] == SOCKS_V5 && buf[1] == SOCKS_CONNECT && buf[2] == 0) {
			switch(buf[3]) {
				case SOCKS_IPV4:
					read_or_err(request_sock, buf+4, 6);
					uint32_t ip = ntohl(*(uint32_t*)(buf+4));
					p = ntohs(*(uint16_t*)(buf+8));
					if (0 >= asprintf(hostp, "%u.%u.%u.%u", (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255 ))
						err(1, "could not convert IP address to string");
					break;
				case SOCKS_IPV6:
					read_or_err(request_sock, buf+4, 18);
					p = ntohs(*(uint16_t*)(buf+20));
					if (0 >= asprintf(hostp, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
							(int)(unsigned char)buf[4+0], (int)(unsigned char)buf[4+1],
							(int)(unsigned char)buf[4+2], (int)(unsigned char)buf[4+3],
							(int)(unsigned char)buf[4+4], (int)(unsigned char)buf[4+5],
							(int)(unsigned char)buf[4+6], (int)(unsigned char)buf[4+7],
							(int)(unsigned char)buf[4+8], (int)(unsigned char)buf[4+9],
							(int)(unsigned char)buf[4+10], (int)(unsigned char)buf[4+11],
							(int)(unsigned char)buf[4+12], (int)(unsigned char)buf[4+13],
							(int)(unsigned char)buf[4+14], (int)(unsigned char)buf[4+15]))
						err(1, "could not convert IPv6 address to string");
					break;
				case SOCKS_DOMAIN:
					read_or_err(request_sock, buf+4, 1);
					count = (int)(unsigned char)buf[4];
					if (count == 0)
						errx(1, "Empty destination in SOCKSv5 request");
					read_or_err(request_sock, buf+5, count);
					buf[5+count] = 0;
					read_or_err(request_sock, buf+5+count+1, 2);
					p = ntohs(*(uint16_t*)(buf+5+count+1));
					if ((*hostp = strdup(buf+5)) == NULL)
						err(1, "strdup");
					break;
				default:
					errx(1, "Unknown SOCKSv5 address type %d", (int)buf[3]);
			}

			if (0 >= asprintf(portp, "%u", (unsigned)p))
				err(1, "could not convert port to string");
			break;
		}

		errx(1, "Illegal SOCKSv5 request"); /* Do not include untrusted user strings in printout! */
	}
	case 'C':
		proxy_read_line(request_sock, buf+1, sizeof(buf)-1);
		if (strncmp(buf, "CONNECT ", 8) == 0) {
			char *host = buf+8;
			char *port = strchr(host, ' ');
			if (port != NULL && port != host) {
				*port = 0;
				port = strrchr(host, ':');
				if (port != NULL && port != host && port[1] != 0) {
					*port++ = 0;
					if (((*hostp = strdup(host)) == NULL) || ((*portp = strdup(port)) == NULL))
						err(1, "strdup");
					proxy_skip_headers(request_sock);
					break;
				}
			}
		}
		errx(1, "Unknown proxy protocol"); /* Do not include untrusted user strings in printout! */
	default:
		errx(1, "Unknown proxy protocol %d", (int)buf[0]);
	}

	return buf[0];
}

void
proxy_send_error_reply(int request_sock, int proxy_proto)
{
	char* reply = NULL;
	int replylen = 0;
	char v4reply[8] = {0, 91, 0, 0, 0, 0, 0, 0};
	char v5reply[10] = {SOCKS_V5, 1, 0, SOCKS_IPV4, 0, 0, 0, 0, 0, 0};
	char* creply = "HTTP/1.1 503 Service Unavailable\r\nProxy-Connection: close\r\nConnection: close\r\n\r\n";

	switch(proxy_proto) {
	case SOCKS_V4:
		reply = v4reply;
		replylen = sizeof(v4reply);
		break;
	case SOCKS_V5:
		reply = v5reply;
		replylen = sizeof(v5reply);
		break;
	case 'C':
		reply = creply;
		replylen = strlen(creply);
		break;
	default:
		errx(1, "can't happen (strange proxy protocol)");
	}

	if (replylen != atomicio(vwrite, request_sock, reply, replylen))
		warn("write failed");
}

void
proxy_send_success_reply(int request_sock, int proxy_proto, int peer_sock)
{
	char* reply = NULL;
	int replylen = 0;
	struct sockaddr_storage sa;
	socklen_t salen = sizeof(sa);

	if (proxy_proto == 'C') {
		char* creply = "HTTP/1.1 200 Connection established\r\n\r\n";
		replylen = strlen(creply);
		if (replylen != atomicio(vwrite, request_sock, creply, replylen))
			warn("write failed");
		return;
	}

	if (getpeername(peer_sock, (void*)&sa, &salen) != 0)
		err(1, "getpeername");

	char v4reply[8] = {0, 90, 0, 0, 0, 0, 0, 0};
	char v5reply4[10] = {SOCKS_V5, 0, 0, SOCKS_IPV4, 0, 0, 0, 0, 0, 0};
	char v5reply6[22] = {SOCKS_V5, 0, 0, SOCKS_IPV6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0, 0};

	switch(sa.ss_family) {
	case AF_INET:
		memcpy(v4reply+4, &((struct sockaddr_in*)&sa)->sin_addr, 4);
		memcpy(v4reply+2, &((struct sockaddr_in*)&sa)->sin_port, 2);
		memcpy(v5reply4+4, &((struct sockaddr_in*)&sa)->sin_addr, 4);
		memcpy(v5reply4+8, &((struct sockaddr_in*)&sa)->sin_port, 2);
		break;
	case AF_INET6:
		if (proxy_proto == SOCKS_V4) {
			warn("SOCKSv4 connection to IPv6 destination");
			break;
		}
		memcpy(v5reply6+4, &((struct sockaddr_in6*)&sa)->sin6_addr, 16);
		memcpy(v5reply6+20, &((struct sockaddr_in6*)&sa)->sin6_port, 2);
		break;
	default:
		errx(1, "can't happen (socket neither AF_INET nor AF_INET6)");
	}

	switch(proxy_proto) {
	case SOCKS_V4:
		reply = v4reply;
		replylen = sizeof(v4reply);
		break;
	case SOCKS_V5:
		if (sa.ss_family == AF_INET) {
			reply = v5reply4;
			replylen = sizeof(v5reply4);
		} else {
			reply = v5reply6;
			replylen = sizeof(v5reply6);
		}

		break;
	default:
		errx(1, "can't happen (strange proxy protocol)");
	}

	if (replylen != atomicio(vwrite, request_sock, reply, replylen))
		warn("write failed");
}
