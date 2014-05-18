/**
 * @file chain_in.c
 * @brief Incoming Chain - API
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
#include <unistd.h>
#include <arpa/inet.h>
#elif defined(COMPILE_WIN32)
#include <windows.h>
#include <winsock2.h>
#endif

#include "skt.h"
#include "sidp.h"

#include "cl_api.h"
#include "el_api.h"
#include "sl_api.h"
#include "dl_api.h"

#include "chain_in.h"

/**
 * @brief Initializes incoming chain 'cid' for packet 'pkt' with options 'opt'
 * @see sidp_send_pkt()
 * @param cid The 'struct chain_in_data' to be initialized
 * @param pkt The SIDP packet to be received
 * @param opt The SIDP packet options
 * @return 0 on success, -1 on error
 */
static int chain_in_init(
		struct chain_in_data *cid,
		const struct sidpopt *opt) {

	/* Reset memory */
	memset(cid, 0, sizeof(struct chain_in_data));

	/* If the message is of type data, all layers shall be initialized */
	if (opt->msg_type == SIDP_MSG_TYPE_DATA) {
		if (cl_data_init(&cid->cl, opt->compress_type) < 0)
			return -1;

		if (el_data_init(&cid->el, opt->cipher_type) < 0)
			return -1;
	}

	/* Initialize session layer. This is common to all message types */
	if (sl_data_init(&cid->sl, opt->session_type) < 0)
		return -1;

	return 0;
}

/**
 * @brief Receives a packet into 'pkt' with options 'opt' from 
 * SIDP connection descriptor 'conn'
 * @see chain_in_init()
 * @see sidp_send_pkt()
 * @param conn The SIDP connection descriptor structure
 * @param cod The initialized 'struct chain_in_data'
 * @param pkt The SIDP packet to be received
 * @param opt The SIDP packet options
 * @return Number of bytes received on success, -1 on error
 */
int chain_in_receive(
		struct sidpconn *conn,
		struct sidppkt *pkt,
		struct sidpopt *opt) {
	uint32_t def_size;
	int rlen, len = 0;
	char *cl_data = NULL;
	char *el_data = NULL;
	char *sl_data = NULL;
	char *raw_data = NULL;
	struct chain_in_data cid;
	struct sl_hdr sl_hdr;
	struct dl_hdr dl_hdr;

	/* Read the incoming description layer */
	if ((rlen = sidp_read_nb(conn, &dl_hdr, sizeof(struct dl_hdr))) < 0)
		return -1;

	/* If the read() size is different than the header size, return error */
	if (((unsigned int) rlen) != sizeof(struct dl_hdr))
		return -2;

	/* decompose description header */
	opt->session_type = ntohs(dl_hdr.session_type);
	opt->cipher_type = ntohs(dl_hdr.cipher_type);
	opt->compress_type = ntohs(dl_hdr.compress_type);
	opt->msg_type = ntohs(dl_hdr.msg_type);
	pkt->msg_size = ntohs(dl_hdr.inf_size);
	def_size = ntohs(dl_hdr.def_size);

	/* If inflate size exceeds SIDP_PKT_MSG_MAX_LEN or
	 * if the deflate size, plus the session and descriptor headers,
	 * is greter than SIDP_PKT_MAX_LEN, return error
	 */
	if ((pkt->msg_size > SIDP_PKT_MSG_MAX_LEN) || ((def_size + SIDP_PKT_HDRS_MAX_LEN) > SIDP_PKT_MAX_LEN))
		return -3;

	/* Initialize incoming chain */
	if (chain_in_init(&cid, opt) < 0)
		return -4;

	/* Allocate enough memory for all layer decomposition */
	if (!(raw_data = (char *) malloc((def_size * 3) + sizeof(struct sl_hdr))))
		return -5;

	sl_data = raw_data;
	el_data = raw_data + def_size + sizeof(struct sl_hdr);
	cl_data = el_data + def_size;

	/* Read the remaining packet data */
	if ((rlen = sidp_read_nb(conn, sl_data, def_size)) < 0) {
		free(raw_data);
		return -6;
	}

	/* If the read() size is different than expected, return error */
	if (((unsigned int) rlen) != def_size) {
		free(raw_data);
		return -7;
	}

	/* Decapsulate session header */
	if ((len = cid.sl.decap(el_data, sl_data, def_size, &sl_hdr)) < 0) {
		free(raw_data);
		return -8;
	}

	/* Decompose session header */
	if (opt->session_type == SL_ENCAP_TYPE_DEFAULT) {
		pkt->sdev = ntohl(sl_hdr.default_hdr.sdev);
		pkt->ddev = ntohl(sl_hdr.default_hdr.ddev);
		pkt->sid = ntohl(sl_hdr.default_hdr.session_id);
	} else {
		free(raw_data);
		return -9;
	}

	/* If msg is of type DATA, we need to decrypt and decompress it */
	if (opt->msg_type == SIDP_MSG_TYPE_DATA) {
		/* Decrypt message */
		if ((len = cid.el.decrypt(opt->key, (unsigned char *) cl_data, (unsigned char *) el_data, len)) < 0) {
			free(raw_data);
			return -10;
		}

		/* Allocate enough memory to fit the inflated packet size */
		if (!(pkt->msg = malloc(pkt->msg_size))) {
			free(raw_data);
			return -11;
		}

		/* Decompress message */
		if ((len = cid.cl.decompress(pkt->msg, pkt->msg_size, cl_data, len)) < 0) {
			free(pkt->msg);
			free(raw_data);
			return -12;
		}

		/* Grant that returned data length from decompression is the
		 * same as the expected message size.
		 */
		if (len != pkt->msg_size) {
			free(pkt->msg);
			free(raw_data);
			return -13;
		}
	} else if ((opt->msg_type == SIDP_MSG_TYPE_AUTH) || (opt->msg_type == SIDP_MSG_TYPE_NEGOTIATE) || (opt->msg_type == SIDP_MSG_TYPE_INIT)) {
		/* If the message isn't of type DATA, there's no encryption
		 * nor compression.
		 */

		/* Allocate packet message memory */
		if (!(pkt->msg = malloc(len))) {
			free(raw_data);
			return -14;
		}

		/* Copy payload to packet message */
		memcpy(pkt->msg, el_data, len);
	} else {
		/* Return error on unrecognized message types */
		free(raw_data);
		return -15;
	}

	/* Free memory */
	free(raw_data);

	return len;
}

