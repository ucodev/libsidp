/**
 * @file sidp.h
 * @brief The header file for sidp.c
 */

/*
   Secure Inter-Device Protocol Library

   Copyright 2012-2014 Pedro A. Hortas (pah@ucodev.org)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/


#ifndef SIDP_H
#define SIDP_H

#ifdef COMPILE_WIN32
#  if BUILDING_DLL
#    define DLLIMPORT __declspec (dllexport)
#  else /* Not BUILDING_DLL */
#    define DLLIMPORT __declspec (dllimport)
#  endif /* Not BUILDING_DLL */
#endif

#include <stdint.h>
#include <time.h>

#include "el_api.h"
#include "sl_api.h"
#include "dl_api.h"
#include "cl_api.h"

/**
 * @def SIDP_PKT_MAX_LEN
 * @brief The maximum packet length allowed to be sent or received
 */
#define SIDP_PKT_MAX_LEN	65535
/*
 * @def SIDP_PKT_HDRS_MAX_LEN
 * @brief The maximum length of the sum of all headers in the SIDP packet
 */
#define SIDP_PKT_HDRS_MAX_LEN	1024
/*
 * @def SIDP_PKT_LAYER_MAX_PAD_LEN
 * @brief The maximum padding size that layers perform on the packet
 */
#define SIDP_PKT_LAYER_MAX_PAD_LEN	128
/*
 * @def SIDP_PKT_MSG_MAX_LEN
 * @brief The maximum size allowed for packet payload (message)
 */
#define SIDP_PKT_MSG_MAX_LEN	(SIDP_PKT_MAX_LEN - SIDP_PKT_HDRS_MAX_LEN - SIDP_PKT_LAYER_MAX_PAD_LEN)
/**
 * @def SIDP_KEY_MAX_LEN
 * @brief The maximum allowed length for the encryption/decryption key
 */
#define SIDP_KEY_MAX_LEN	32
/**
 * @def SIDP_USER_MAX_LEN
 * @brief The maximum allowed length for username (SRP)
 */
#define SIDP_USER_MAX_LEN	128
/* Message types */
/**
 * @brief The possible message types to be used on sidp_pkt_set_opt()
 * @see sidp_pkt_set_opt()
 */
enum {
	SIDP_MSG_TYPE_DATA,
	SIDP_MSG_TYPE_AUTH,
	SIDP_MSG_TYPE_NEGOTIATE,
	SIDP_MSG_TYPE_INIT
};

/**
 * @brief Support flags for sidp structure
 */
enum {
	SIDP_SUPPORT_CIPHER_AES256_FL,
	SIDP_SUPPORT_CIPHER_XSALSA20_FL,
	SIDP_SUPPORT_CIPHER_CHACHA_AVX_FL,
	SIDP_SUPPORT_CIPHER_CHACHA_AVX2_FL,
	SIDP_SUPPORT_COMPRESS_LZO_FL,
	SIDP_SUPPORT_COMPRESS_ZLIB_FL,
	SIDP_SUPPORT_COMPRESS_FASTLZ_FL,
	SIDP_SUPPORT_ENCAP_DEFAULT_FL
};
/**
 * @brief Negotiate flags for sidp structure
 */
enum {
	SIDP_NEGOTIATE_CIPHER_AES256_FL,
	SIDP_NEGOTIATE_CIPHER_XSALSA20_FL,
	SIDP_NEGOTIATE_CIPHER_CHACHA_AVX_FL,
	SIDP_NEGOTIATE_CIPHER_CHACHA_AVX2_FL,
	SIDP_NEGOTIATE_COMPRESS_LZO_FL,
	SIDP_NEGOTIATE_COMPRESS_ZLIB_FL,
	SIDP_NEGOTIATE_COMPRESS_FASTLZ_FL,
	SIDP_NEGOTIATE_ENCAP_DEFAULT_FL
};
/**
 * @brief Status flags for sidp structure
 */
enum {
	SIDP_INITIATED_FL,
	SIDP_NEGOTIATED_FL,
	SIDP_AUTHENTICATED_FL
};
/**
 * @brief connection types
 */
enum {
	SIDP_CONN_TYPE_NONE,
	SIDP_CONN_TYPE_NORMAL,
	SIDP_CONN_TYPE_ROUTING,
	SIDP_CONN_TYPE_PERSISTENT
};


/* Structures */
struct sidpconn {
	int fd;
	uint32_t sdev;
	uint32_t ddev;
	uint32_t sid;
	char user[SIDP_USER_MAX_LEN + 1];
	unsigned char key[SIDP_KEY_MAX_LEN + 1];
	uint32_t negotiate_flags;
	uint32_t support_flags;
	uint32_t status_flags;
	uint16_t type;

	/* Connection Statistics */
	time_t last_fd_write;
	time_t last_fd_read;

	uint32_t bytes_out;
	uint32_t bytes_in;
};

/**
 * @brief The packet structure to be used on sidp_pkt_send() and sidp_pkt_recv()
 * @see sidp_pkt_send()
 * @see sidp_pkt_recv()
 */
struct sidppkt {
	uint32_t sdev;
	uint32_t ddev;
	uint32_t sid;
	uint16_t msg_size;
	void *msg;
};

/**
 * @brief The packet options to be used on sidp_pkt_set_opt()
 * @see sidp_pkt_set_opt()
 * @see sidp_pkt_send()
 * @see sidp_pkt_recv()
 */
struct sidpopt {
	uint16_t session_type;
	uint16_t compress_type;
	uint16_t cipher_type;
	uint16_t msg_type;

	unsigned char key[SIDP_KEY_MAX_LEN + 1];
};

/* Prototypes */
/* API */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void sidp_pkt_set_opt(
		struct sidpopt *opt,
		uint16_t session_type,
		uint16_t cipher_type,
		uint16_t compress_type,
		uint16_t msg_type,
		const unsigned char *key);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_pkt_raw_send(struct sidpconn *conn, void *buf, size_t len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_pkt_raw_recv(struct sidpconn *conn, void *buf, size_t *len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_pkt_send(
		struct sidpconn *conn,
		const struct sidppkt *pkt,
		const struct sidpopt *opt);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_pkt_recv(
		struct sidpconn *conn,
		struct sidppkt *pkt,
		struct sidpopt *opt);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void sidp_conn_init(
		struct sidpconn *conn,
		int fd,
		uint32_t sdev,
		uint32_t ddev,
		uint32_t sid,
		uint16_t type);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void sidp_conn_set_key(struct sidpconn *conn, const unsigned char *key);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void sidp_conn_set_support(struct sidpconn *conn, unsigned int flag);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void sidp_conn_set_support_flags(struct sidpconn *conn, uint32_t flags);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_conn_close(struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_conn_initiated(const struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_conn_authenticated(const struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_conn_negotiated(const struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_conn_fd(const struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
uint32_t sidp_conn_ddev(const struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
uint32_t sidp_conn_sdev(const struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
uint32_t sidp_conn_sid(const struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
uint16_t sidp_conn_type(const struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
uint32_t sidp_conn_stat_read_bytes(const struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
uint32_t sidp_conn_stat_write_bytes(const struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
time_t sidp_conn_stat_last_write(const struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
time_t sidp_conn_stat_last_read(const struct sidpconn *conn);


/* Final headers */
#include "seq_auth.h"
#include "seq_data.h"
#include "seq_negotiation.h"
#include "seq_init.h"


#endif
