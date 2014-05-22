/**
 * @file seq_negotiation.c
 * @brief SIDP - Negotiation Sequence API
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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef COMPILE_POSIX
#include <arpa/inet.h>
#elif defined(COMPILE_WIN32)
#include <windows.h>
#include <winsock2.h>
#endif

#include "sidp.h"
#include "bitops.h"
#include "seq_negotiation.h"

/**
 * @brief Send a negotiation sequence packet
 * @param conn SIDP connection descriptor
 * @param data Negotiation data to be sent
 */
static int sidp_seq_negotiation_pkt_send(
		struct sidpconn *conn,
		const struct neg_data *data) {
	struct sidpopt opt;
	struct sidppkt pkt;

	/* Reset options and packet memory */
	memset(&pkt, 0, sizeof(struct sidppkt));
	memset(&opt, 0, sizeof(struct sidpopt));

	/* Set SIDP packet options */
	sidp_pkt_set_opt(&opt, SL_ENCAP_TYPE_DEFAULT, 0, 0, SIDP_MSG_TYPE_NEGOTIATE, NULL);

	/* Create SIDP packet */
	pkt.sdev = conn->sdev;
	pkt.ddev = conn->ddev;
	pkt.sid = conn->sid;
	pkt.msg = (void *) data;
	pkt.msg_size = sizeof(struct neg_data);

	/* Dispatch packet */
	if (sidp_pkt_send(conn, &pkt, &opt) < 0)
		return -1;

	return 0;
}

/**
 * @brief Retrieves a negotiation sequence packet
 * @param conn SIDP connection descriptor
 * @param data Received negotiation sequence data buffer
 */
static int sidp_seq_negotiation_pkt_recv(
		struct sidpconn *conn,
		struct neg_data *data) {
	struct sidpopt opt;
	struct sidppkt pkt;

	/* Reset data, options and packet memory */
	memset(data, 0, sizeof(struct neg_data));
	memset(&pkt, 0, sizeof(struct sidppkt));
	memset(&opt, 0, sizeof(struct sidpopt));

	/* Receive packet */
	sidp_pkt_recv(conn, &pkt, &opt);

	/* Check if the received message type is different than
	 * SIDP_MSG_TYPE_NEGOTIATE
	 */
	if (opt.msg_type != SIDP_MSG_TYPE_NEGOTIATE)
		return -1;

	/* Grant that the length of the received data is the same as expected */
	if (pkt.msg_size != sizeof(struct neg_data))
		return -2;

	/* Copy packet message to data buffer */
	memcpy(data, pkt.msg, pkt.msg_size);

	/* Free packet memory */
	free(pkt.msg);

	return 0;
}

/**
 * @brief Initializes user negotiation sequence
 * @param conn SIDP connection descriptor
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_negotiation_user(struct sidpconn *conn) {
	struct neg_data neg_data;

	/* Check if the connection is initiated */
	if (!test_bit(&conn->status_flags, SIDP_INITIATED_FL))
		return -1;

	/* Check if the connection is authenticated */
	if (!test_bit(&conn->status_flags, SIDP_AUTHENTICATED_FL))
		return -2;

	/* Send support flags to remote host */
	neg_data.flags = htonl(conn->support_flags);

	if (sidp_seq_negotiation_pkt_send(conn, &neg_data) < 0)
		return -3;

	/* Receive support flags of the remote host based on the sent
	 * support flags
	 */
	if (sidp_seq_negotiation_pkt_recv(conn, &neg_data) < 0)
		return -4;

	neg_data.flags = ntohl(neg_data.flags);

	/* Test compression negotiation */
	if (test_bit(&neg_data.flags, SIDP_SUPPORT_COMPRESS_LZO_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_COMPRESS_LZO_FL);
	} else if (test_bit(&neg_data.flags, SIDP_SUPPORT_COMPRESS_FASTLZ_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_COMPRESS_FASTLZ_FL);
	} else if (test_bit(&neg_data.flags, SIDP_SUPPORT_COMPRESS_ZLIB_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_COMPRESS_ZLIB_FL);
	} else {
		return -5;
	}

	/* Test encryption negotiation */
	if (test_bit(&neg_data.flags, SIDP_SUPPORT_CIPHER_XSALSA20_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_CIPHER_XSALSA20_FL);
	} else if (test_bit(&neg_data.flags, SIDP_SUPPORT_CIPHER_CHACHA_AVX_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_CIPHER_CHACHA_AVX_FL);
	} else if (test_bit(&neg_data.flags, SIDP_SUPPORT_CIPHER_CHACHA_AVX2_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_CIPHER_CHACHA_AVX2_FL);
	} else if (test_bit(&neg_data.flags, SIDP_SUPPORT_CIPHER_AES256_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_CIPHER_AES256_FL);
	} else {
		return -6;
	}

	/* Test encapsulation negotiation */
	if (test_bit(&neg_data.flags, SIDP_SUPPORT_ENCAP_DEFAULT_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_ENCAP_DEFAULT_FL);
	} else {
		return -7;
	}

	/* Set status to negotiated */
	set_bit(&conn->status_flags, SIDP_NEGOTIATED_FL);

	return 0;
}

/**
 * @brief Initializes host negotiation sequence
 * @param conn SIDP connection descriptor
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_negotiation_host(struct sidpconn *conn) {
	struct neg_data neg_data;

	/* Check if the connection is initiated */
	if (!test_bit(&conn->status_flags, SIDP_INITIATED_FL))
		return -1;

	/* Check if the connection is authenticated */
	if (!test_bit(&conn->status_flags, SIDP_AUTHENTICATED_FL))
		return -2;

	/* Receive support flags of the remote host */
	if (sidp_seq_negotiation_pkt_recv(conn, &neg_data) < 0)
		return -3;

	neg_data.flags = ntohl(neg_data.flags);

	/* Cross support flags of both end-points */
	neg_data.flags &= conn->support_flags;

	neg_data.flags = htonl(neg_data.flags);

	/* Send data to the remote host */
	if (sidp_seq_negotiation_pkt_send(conn, &neg_data) < 0)
		return -4;

	neg_data.flags = ntohl(neg_data.flags);

	/* Test compression negotiation */
	if (test_bit(&neg_data.flags, SIDP_SUPPORT_COMPRESS_LZO_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_COMPRESS_LZO_FL);
	} else if (test_bit(&neg_data.flags, SIDP_SUPPORT_COMPRESS_FASTLZ_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_COMPRESS_FASTLZ_FL);
	} else if (test_bit(&neg_data.flags, SIDP_SUPPORT_COMPRESS_ZLIB_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_COMPRESS_ZLIB_FL);
	} else {
		return -5;
	}

	/* Test encryption negotiation */
	if (test_bit(&neg_data.flags, SIDP_SUPPORT_CIPHER_XSALSA20_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_CIPHER_XSALSA20_FL);
	} else if (test_bit(&neg_data.flags, SIDP_SUPPORT_CIPHER_CHACHA_AVX_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_CIPHER_CHACHA_AVX_FL);
	} else if (test_bit(&neg_data.flags, SIDP_SUPPORT_CIPHER_CHACHA_AVX2_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_CIPHER_CHACHA_AVX2_FL);
	} else if (test_bit(&neg_data.flags, SIDP_SUPPORT_CIPHER_AES256_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_CIPHER_AES256_FL);
	} else {
		return -6;
	}

	/* Test encapsulation negotiation */
	if (test_bit(&neg_data.flags, SIDP_SUPPORT_ENCAP_DEFAULT_FL)) {
		set_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_ENCAP_DEFAULT_FL);
	} else {
		return -7;
	}

	/* Set status to negotiated */
	set_bit(&conn->status_flags, SIDP_NEGOTIATED_FL);

	return 0;
}

