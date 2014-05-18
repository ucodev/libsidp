/**
 * @file sidp.c
 * @brief SIDP Packet Interface Level.
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


#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef COMPILE_POSIX
#include <unistd.h>
#include <arpa/inet.h>
#elif defined(COMPILE_WIN32)
#include <winsock2.h>
#include <windows.h>
#endif


#include "sidp.h"
#include "bitops.h"
#include "skt.h"

#include "chain_out.h"
#include "chain_in.h"

/**
 * @brief Setup the 'opt' param to be used in the send/receive functions
 * @see sidp_pkt_send()
 * @see sidp_pkt_recv()
 * @see SL_ENCAP_TYPE_DEFAULT
 * @see CL_COMPRESS_TYPE_LZO
 * @see CL_COMPRESS_TYPE_ZLIB
 * @see EL_CIPHER_TYPE_AES256
 * @see EL_CIPHER_TYPE_XSALSA20
 * @param opt The packet options structure 'struct sidpopt'
 * @param session_type The session type. May be one of the following values:
 * SL_ENCAP_TYPE_DEFAULT
 * @param cipher_type The cipher type. May be one of the following values:
 * EL_CIPHER_TYPE_AES256
 * EL_CIPHER_TYPE_XSALSA20
 * @param compress_type The compress type. May be one of the following values:
 * CL_COMPRESS_TYPE_LZO
 * CL_COMPRESS_TYPE_ZLIB
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void sidp_pkt_set_opt(
		struct sidpopt *opt,
		uint16_t session_type,
		uint16_t cipher_type,
		uint16_t compress_type,
		uint16_t msg_type,
		const unsigned char *key) {
	memset(opt, 0, sizeof(struct sidpopt));
	opt->session_type = session_type;
	opt->cipher_type = cipher_type;
	opt->compress_type = compress_type;
	opt->msg_type = msg_type;

	if (msg_type == SIDP_MSG_TYPE_DATA)
		strncpy((char *) opt->key, (const char *) key, strlen((const char *) key) >= sizeof(opt->key) ? sizeof(opt->key) - 1 : strlen((const char *) key));
}

/**
 * @brief Sends a RAW packet through fd
 * @param fd The connections file descriptor
 * @param buf The buffer from were the packet will be read
 * @param len The size of the packet
 * @return The number of bytes sent on success. Negative on error.
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_pkt_raw_send(struct sidpconn *conn, void *buf, size_t len) {
	return sidp_write_nb(conn, buf, len);
}

/**
 * @brief Receives a RAW packet from fd
 * @param fd The SIDP Connection structure
 * @param buf The buffer to were the packet will be written
 * @param len The size of the packet
 * @return The number of bytes received on success. Negative on error.
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_pkt_raw_recv(struct sidpconn *conn, void *buf, size_t *len) {
	uint32_t def_size;
	int rlen;
	char *raw_data = (char *) buf;
	struct dl_hdr *dl_hdr = (struct dl_hdr *) raw_data;

	/* Read the incoming description layer */
	if ((rlen = sidp_read_nb(conn, dl_hdr, sizeof(struct dl_hdr))) < 0)
		return -1;

	/* If the read() size is different than the header size, return error */
	if (rlen != sizeof(struct dl_hdr))
		return -2;

	/* decompose description header */
	def_size = ntohs(dl_hdr->def_size);

	/* if the deflate size, plus the session and descriptor headers,
	 * is greter than SIDP_PKT_MAX_LEN, return error
	 */
	if ((def_size + SIDP_PKT_HDRS_MAX_LEN) > SIDP_PKT_MAX_LEN)
		return -3;

	/* Read the remaining packet data */
	if ((rlen = sidp_read_nb(conn, raw_data + sizeof(struct dl_hdr), def_size)) < 0)
		return -4;

	/* Set total read bytes to 'len' and return */
	return (*len = (def_size + sizeof(struct dl_hdr)));
}

/**
 * @brief Sends the packet 'pkt' with options 'opt' through 'conn'
 * @see sidp_pkt_set_opt()
 * @param conn The SIDP connection description structure
 * @param pkt The packet to be sent
 * @param opt The packet options, setted by the sidp_pkt_set_opt() function
 * @return Number of bytes sent on success, -1 on error.
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_pkt_send(
		struct sidpconn *conn,
		const struct sidppkt *pkt,
		const struct sidpopt *opt) {
	return chain_out_dispatch(conn, pkt, opt);
}

/**
 * @brief Receives a packet 'pkt' from 'conn' and fills 'opt'
 * @param conn The SIDP connection description structure
 * @param pkt The packet structure that will be filled
 * @param opt The packet options extracted from the received packet
 * @return Number of bytes received on success, -1 on error.
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_pkt_recv(
		struct sidpconn *conn,
		struct sidppkt *pkt,
		struct sidpopt *opt) {
	return chain_in_receive(conn, pkt, opt);
}

/**
 * @brief Creates a sidpconn structure to be used in sequence functions
 * @see sidp_data_seq_send()
 * @see sidp_data_seq_recv()
 * @param conn The connection settings to be initialized
 * @param fd The file descriptor of the ocnnection (blocking scoket)
 * @param sdev The source device ID
 * @param ddev The destination device ID
 * @param sid The session ID of the connection
 * @param type The connection type
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void sidp_conn_init(
		struct sidpconn *conn,
		int fd,
		uint32_t sdev,
		uint32_t ddev,
		uint32_t sid,
		uint16_t type) {

	memset(conn, 0, sizeof(struct sidpconn));
	conn->fd = fd;
	conn->sdev = sdev;
	conn->ddev = ddev;
	conn->sid = sid;
	conn->type = type;
}
/**
 * @brief Set connection key to 'conn' structure
 * @param conn SIDP connection settings
 * @param key The connection key used for cipher/decipher data
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void sidp_conn_set_key(struct sidpconn *conn, const unsigned char *key) {
	strncpy((char *) conn->key, (const char *) key, strlen((const char *) key) >= sizeof(conn->key) ? sizeof(conn->key) - 1 : strlen((const char *) key));
}

/**
 * @brief Set a support flag to connection 'conn'
 * @param conn SIDP connection settings
 * @param flag The support flag to be set
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void sidp_conn_set_support(struct sidpconn *conn, unsigned int flag) {
	set_bit(&conn->support_flags, flag);
}

/**
 * @brief Set the entire support flags field atomically on connection 'conn'
 * @param conn SIDP Connection Settings
 * @param flags Support flags field
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void sidp_conn_set_support_flags(struct sidpconn *conn, uint32_t flags) {
	conn->support_flags = flags;
}

/**
 * @brief Destroy a SIDP connection refered by 'conn'
 * @param conn SIDP connection settings
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_conn_close(struct sidpconn *conn) {
	int ret;

	ret = close(conn->fd);

	memset(conn, 0, sizeof(struct sidpconn));

	conn->type = SIDP_CONN_TYPE_NONE;

	return ret;
}

/**
 * @brief Indicates whether the connection is initiated
 * @param conn SIDP Connections structure
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_conn_initiated(const struct sidpconn *conn) {
	return test_bit(&conn->status_flags, SIDP_INITIATED_FL);
}

/**
 * @brief Indicates whether the connection is authenticated
 * @param conn SIDP Connections structure
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_conn_authenticated(const struct sidpconn *conn) {
	return test_bit(&conn->status_flags, SIDP_AUTHENTICATED_FL);
}

/**
 * @brief Indicates whether the connection is negotiated
 * @param conn SIDP Connection structure
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_conn_negotiated(const struct sidpconn *conn) {
	return test_bit(&conn->status_flags, SIDP_NEGOTIATED_FL);
}

/**
 * @brief Returns the connection file descriptor
 * @param conn SIDP connection structure
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_conn_fd(const struct sidpconn *conn) {
	return conn->fd;
}

/**
 * @brief Returns the destination device
 * @param conn SIDP connection structure
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
uint32_t sidp_conn_ddev(const struct sidpconn *conn) {
	return conn->ddev;
}

/**
 * @brief Returns the source device
 * @param conn SIDP connection structure
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
uint32_t sidp_conn_sdev(const struct sidpconn *conn) {
	return conn->sdev;
}

/**
 * @brief Returns the session id
 * @param conn SIDP connection structure
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
uint32_t sidp_conn_sid(const struct sidpconn *conn) {
	return conn->sid;
}

/**
 * @brief Returns the connection type
 * @param conn SIDP connection structure
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
uint16_t sidp_conn_type(const struct sidpconn *conn) {
	return conn->type;
}

/**
 * @brief Returns the total bytes received since the connection was created.
 * @param conn SIDP connection structure
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
uint32_t sidp_conn_stat_read_bytes(const struct sidpconn *conn) {
	return conn->bytes_in;
}

/**
 * @brief Returns the total bytes sent since the connection was created.
 * @param conn SIDP connection structure
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
uint32_t sidp_conn_stat_write_bytes(const struct sidpconn *conn) {
	return conn->bytes_out;
}

/**
 * @brief Returns the last time a write operation was performed on the
 * connection
 * @param conn SIDP connection structure
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
time_t sidp_conn_stat_last_write(const struct sidpconn *conn) {
	return conn->last_fd_write;
}

/**
 * @brief Returns the last time a read operation was performed on the
 * connection
 * @param conn SIDP connection structure
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
time_t sidp_conn_stat_last_read(const struct sidpconn *conn) {
	return conn->last_fd_read;
}

