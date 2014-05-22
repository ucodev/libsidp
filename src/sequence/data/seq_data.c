/**
 * @file seq_data.c
 * @brief SIDP - Data Sequence API
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
#include <stdlib.h>
#include <string.h>

#include "sidp.h"
#include "bitops.h"


/**
 * @brief Gets the encapsulation type, based on 'conn' settings.
 * @see SL_ENCAP_TYPE_DEFAULT
 * @param conn The SIDP connection structure
 * @return The encapsulation type on success, negative integer on error.
 */
static int sidp_seq_data_get_encap_type(const struct sidpconn *conn) {
	if (test_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_ENCAP_DEFAULT_FL))
		return SL_ENCAP_TYPE_DEFAULT;

	/* This shall never happen. If no agreement is made in the negotiation
	 * sequence, we'll never be here. This is just to avoid compiler
	 * warnings.
	 */

	return -1;
}

/**
 * @brief Gets the compress type, based on 'conn' settings.
 * @see CL_COMPRESS_TYPE_LZO
 * @see CL_COMPRESS_TYPE_ZLIB
 * @param conn The SIDP connection structure
 * @return The compress type on success, negative integer on error.
 */
static int sidp_seq_data_get_compress_type(const struct sidpconn *conn) {
	if (test_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_COMPRESS_LZO_FL))
		return CL_COMPRESS_TYPE_LZO;

	if (test_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_COMPRESS_FASTLZ_FL))
		return CL_COMPRESS_TYPE_FASTLZ;

#ifndef COMPILE_WIN32
	if (test_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_COMPRESS_ZLIB_FL))
		return CL_COMPRESS_TYPE_ZLIB;
#endif

	/* This shall never happen. If no agreement is made in the negotiation
	 * sequence, we'll never be here. This is just to avoid compiler
	 * warnings.
	 */

	return -1;
}

/**
 * @brief Gets the cipher type, based on 'conn' settings.
 * @see EL_CIPHER_TYPE_XSALSA20
 * @see EL_CIPHER_TYPE_AES256
 * @param conn The SIDP connection structure
 * @return The cipher type on success, negative integer on error.
 */
static int sidp_seq_data_get_cipher_type(const struct sidpconn *conn) {
#ifndef COMPILE_WIN32
	if (test_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_CIPHER_XSALSA20_FL))
		return EL_CIPHER_TYPE_XSALSA20;

	if (test_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_CIPHER_CHACHA_AVX_FL))
		return EL_CIPHER_TYPE_CHACHA_AVX;

	if (test_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_CIPHER_CHACHA_AVX2_FL))
		return EL_CIPHER_TYPE_CHACHA_AVX2;
#endif

	if (test_bit(&conn->negotiate_flags, SIDP_NEGOTIATE_CIPHER_AES256_FL))
		return EL_CIPHER_TYPE_AES256;

	/* This shall never happen. If no agreement is made in the negotiation
	 * sequence, we'll never be here. This is just to avoid compiler
	 * warnings.
	 */

	return -1;
}

/**
 * @brief Sends 'data' of length 'len' with the 'conn' settings.
 * @param conn The SIDP connection structure
 * @param data The pointer to a buffer containing the data to be sent
 * @param len The length of the data to be sent
 * @return 0 on success, negative integer on error.
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_data_send(
		struct sidpconn *conn,
		const void *data,
		size_t len) {
	struct sidpopt opt;
	struct sidppkt pkt;

	/* Check if the connection is initiated */
	if (!test_bit(&conn->status_flags, SIDP_INITIATED_FL))
		return -1;

	/* Ensure that connection is authenticated */
	if (!test_bit(&conn->status_flags, SIDP_AUTHENTICATED_FL))
		return -2;

	/* Ensure that connection is negotiated */
	if (!test_bit(&conn->status_flags, SIDP_NEGOTIATED_FL))
		return -3;

	/* Set packet options */
	sidp_pkt_set_opt(&opt, sidp_seq_data_get_encap_type(conn), sidp_seq_data_get_cipher_type(conn), sidp_seq_data_get_compress_type(conn), SIDP_MSG_TYPE_DATA, conn->key);

	/* Create packet */
	pkt.sdev = conn->sdev;
	pkt.ddev = conn->ddev;
	pkt.sid = conn->sid;
	pkt.msg = (void *) data;
	pkt.msg_size = len;

	/* Dispatch packet */
	if (sidp_pkt_send(conn, &pkt, &opt) < 0)
		return -4;

	return 0;
}

/**
 * @brief Receives data into param 'data' and sets 'len' with the length of 
 * the data received.
 * @param conn The SIDP connection structure
 * @param data The pointer to a buffer to where data received will be copied
 * @param len The length of received data
 * @return 0 on success, negative integer on error.
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_data_recv(
		struct sidpconn *conn,
		void *data,
		size_t *len) {
	struct sidpopt opt;
	struct sidppkt pkt;

	/* Check if the connection is initiated */
	if (!test_bit(&conn->status_flags, SIDP_INITIATED_FL))
		return -1;

	/* Ensure that connection is authenticated */
	if (!test_bit(&conn->status_flags, SIDP_AUTHENTICATED_FL))
		return -2;

	/* Ensure that connection is negotiated */
	if (!test_bit(&conn->status_flags, SIDP_NEGOTIATED_FL))
		return -3;

	/* Set cipher key */
	sidp_pkt_set_opt(&opt, 0, 0, 0, SIDP_MSG_TYPE_DATA, conn->key);

	/* Receive a packet */
	if (sidp_pkt_recv(conn, &pkt, &opt) < 0)
		return -4;

	/* Copy packet buffer and set its length */
	memcpy(data, pkt.msg, pkt.msg_size);
	*len = pkt.msg_size;

	/* Destroy packet buffer */
	free(pkt.msg);

	return 0;
}

