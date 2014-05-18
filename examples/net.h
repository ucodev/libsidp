/**
 * @file net.h
 * @brief Header file for net.c of the CALL
 */
#ifndef CALL_NET_H
#define CALL_NET_H

/************************************/
/* BEGIN - OS interface abstraction */
/************************************/

/* POSIX or BSD */
#ifdef COMPILE_POSIX
/* Headers */
#include <unistd.h>
#include <netdb.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>

/* Type abstractions */
typedef int sock_t;
typedef struct sockaddr_in sockaddr_in_t;
typedef struct hostent hostent_t;

#elif defined(COMPILE_WIN32)
/* Windows */
/* Headers */
#include <windows.h>

/* Type abstractions */
typedef SOCKET sock_t;
typedef SOCKADDR_IN sockaddr_in_t;
typedef HOSTENT hostent_t;

#endif

/***********************************/
/* END - OS interface abstraction  */
/***********************************/

/* Prototypes */
sock_t example_net_stream_connect(const char *host, uint16_t port);
sock_t example_net_stream_listen(const char *addr, uint16_t port, int backlog);
sock_t example_net_stream_accept(sock_t fd, uint32_t *raddr);


#endif
