/**
 * @file net.c
 * @brief CALL Network Level Abstraction API
 */
#include <string.h>
#include <stdint.h>

#include "net.h"

/**
 * @brief Connect to a remote host and return the connection file descriptor
 * @param host Remote hostname or IP address
 * @param port Remote TCP port
 * @return Connection file descriptor on success, -1 on error
 */
sock_t example_net_stream_connect(const char *host, uint16_t port) {
	sock_t fd;
	sockaddr_in_t addr;
	hostent_t *he;

	/* Translate 'host' param */
	if (!(he = gethostbyname(host)))
		return -1;

	/* Create socket */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;

	/* Setup the sockaddr_in structure */
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	/* FIXME: potencial wrong byte order for arch != x86/x64 */
	memcpy(&addr.sin_addr, he->h_addr, he->h_length);

	/* Connect to end-point */
	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	/* Return file descriptor */
	return fd;
}

/**
 * @brief Listens to a TCP port for incoming connections
 * @param addr Local address to bind() on
 * @param port Local port to bind() on
 * @param backlog same as for listen()
 * @return Bound file descriptor on success, -1 on error
 */
sock_t example_net_stream_listen(const char *addr, uint16_t port, int backlog) {
	int optval = 1;
	sock_t fd;
	sockaddr_in_t l_addr;
	hostent_t *he;

	/* Setup the sockaddr_in structure */
	l_addr.sin_port = htons(port);
	l_addr.sin_family = AF_INET;

	/* If local addr isn't NULL, use it on sockaddr_in structure */
	if (addr) {
		if (!(he = gethostbyname(addr)))
			return -1;

		/* FIXME: potencial wrong byte order for arch != x86/x64 */
		memcpy(&l_addr.sin_addr, he->h_addr, he->h_length);
	} else {
		/* If local addr is NULL, we'll bind() on 0.0.0.0 */
		l_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	}

	/* Create a file descriptor to be bound */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;

	/* Set socket options */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
		close(fd);
		return -1;
	}

	/* bind() file descriptor */
	if (bind(fd, (struct sockaddr *) &l_addr, sizeof(sockaddr_in_t)) < 0) {
		close(fd);
		return -1;
	}

	/* Listen for connections */
	if (listen(fd, backlog) < 0) {
		close(fd);
		return -1;
	}

	/* Return file descriptor */
	return fd;
}

/**
 * @brief Accepts an incoming connection.
 * @see example_net_stream_listen()
 * @param fd Bound file descriptor returned by example_net_stream_listen()
 * @param raddr Remote IP address
 * @return File descriptor of the accepted connection on success, -1 on error
 */
sock_t example_net_stream_accept(sock_t fd, uint32_t *raddr) {
	sock_t fd_acpt;
	socklen_t len = sizeof(sockaddr_in_t);
	sockaddr_in_t r_addr;

	/* Accept incoming connection */
	if ((fd_acpt = accept(fd, (struct sockaddr *) &r_addr, &len)) < 0)
		return -1;

	/* Retrieve remote address */
	*raddr = ntohl(r_addr.sin_addr.s_addr);

	/* Return file descriptor of the accepted connection */
	return fd_acpt;
}

