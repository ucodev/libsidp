/**
 * @file chain_out.c
 * @brief Outgoing Chain - API
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

#include "chain_out.h"

/**
 * @brief Initializes outgoing chain 'cod' for packet 'pkt' with options 'opt'
 * @see sidp_send_pkt()
 * @param cod The 'struct chain_out_data' to be initialized
 * @param pkt The SIDP packet to be dispached
 * @param opt The SIDP packet options
 * @return 0 on success, -1 on error
 */
static int chain_out_init(
		struct chain_out_data *cod,
		const struct sidpopt *opt) {

	/* Reset memory */
	memset(cod, 0, sizeof(struct chain_out_data));

	/* If the message is of type data, all layers shall be initialized */
	if (opt->msg_type == SIDP_MSG_TYPE_DATA) {
		if (cl_data_init(&cod->cl, opt->compress_type) < 0)
			return -1;

		if (el_data_init(&cod->el, opt->cipher_type) < 0)
			return -1;
	}

	/* Initialize session layer. This is common to all message types */
	if (sl_data_init(&cod->sl, opt->session_type) < 0)
		return -1;

	return 0;
}

/**
 * @brief Dispatches the packet 'pkt' with options 'opt' through
 * file descriptor 'fd'
 * @see chain_out_init()
 * @see sidp_send_pkt()
 * @param conn The SIDP connections descriptor structure
 * @param cod The initialized 'struct chain_out_data'
 * @param pkt The SIDP packet to be dispached
 * @param opt The SIDP packet options
 * @return Number of bytes sent on success, -1 on error
 */
int chain_out_dispatch(
		struct sidpconn *conn,
		const struct sidppkt *pkt,
		const struct sidpopt *opt) {
	int wlen, len = 0;
	void *cl_data = NULL;
	void *el_data = NULL;
	void *sl_data = NULL;
	struct chain_out_data cod;
	struct sl_hdr sl_hdr;
	struct dl_hdr dl_hdr;

	/* Return error if msg size exceeds SIDP_PKT_MAX_LEN */
	if (pkt->msg_size > SIDP_PKT_MSG_MAX_LEN)
		return -1;

	/* Initialize outgoing chain */
	if (chain_out_init(&cod, opt) < 0)
		return -2;

	/* If msg is of type DATA, we need to compress and encrypt it */
	if (opt->msg_type == SIDP_MSG_TYPE_DATA) {
		/* Allocate enough memory for msg compression */
		if (!(cl_data = malloc(cod.cl.compress_output_len(pkt->msg_size))))
			return -3;

		/* Compress message */
		if ((len = cod.cl.compress(cl_data, pkt->msg, pkt->msg_size)) < 0) {
			free(cl_data);
			return -4;
		}

		/* Allocate enough memory for msg encryption */
		if (!(el_data = malloc(cod.el.encrypt_output_len(len)))) {
			free(cl_data);
			return -5;
		}

		/* Encrypt message */
		if ((len = cod.el.encrypt(opt->key, (unsigned char *) el_data, (const unsigned char *) cl_data, len)) < 0) {
			free(cl_data);
			free(el_data);
			return -6;
		}

		/* Free allocated memory used for compression */
		free(cl_data);
	} else if ((opt->msg_type != SIDP_MSG_TYPE_AUTH) && (opt->msg_type != SIDP_MSG_TYPE_NEGOTIATE) && (opt->msg_type != SIDP_MSG_TYPE_INIT)) {
		/* Return error on unrecognized message types */
		return -7;
	}

	/* Compose session layer. This is common for all msg types */

	/* Allocate enough memory for msg session encapsulation and
	 * for metadata indicating the deflated size, inflated size and
	 * session type used in the packet.
	 */
	if (!(sl_data = malloc(cod.sl.encap_output_len((len ? len : pkt->msg_size) + sizeof(struct dl_hdr))))) {
		free(el_data);
		return -8;
	}

	/* Craft session header */
	if (opt->session_type == SL_ENCAP_TYPE_DEFAULT) {
		sl_hdr.default_hdr.sdev = htonl(pkt->sdev);
		sl_hdr.default_hdr.ddev = htonl(pkt->ddev);
		sl_hdr.default_hdr.session_id = htonl(pkt->sid);
	} else {
		/* If session type isn't recognized, return error. */
		if (el_data)
			free(el_data);

		free(sl_data);

		return -9;
	}

	/* Encapsulate packet with session layer */
	if ((len = cod.sl.encap(((char *) sl_data) + sizeof(struct dl_hdr), el_data ? el_data : pkt->msg, len ? len : pkt->msg_size, &sl_hdr)) < 0) {
		if (el_data)
			free(el_data);

		free(sl_data);

		return -10;
	}

	/* If we used encryption, release the used memory */
	if (el_data)
		free(el_data);

	/* Craft sidp packet header */
	dl_hdr.inf_size = htons(pkt->msg_size);
	dl_hdr.def_size = htons(len);
	dl_hdr.session_type = htons(opt->session_type);
	dl_hdr.cipher_type = htons(opt->cipher_type);
	dl_hdr.compress_type = htons(opt->compress_type);
	dl_hdr.msg_type = htons(opt->msg_type);

	memcpy(sl_data, &dl_hdr, sizeof(struct dl_hdr));

	/* Validate that total packet size isn't greater than excepted */
	if ((len + sizeof(struct dl_hdr)) > SIDP_PKT_MAX_LEN)
		return -11;

	/* Dispatch packet */
	if ((wlen = sidp_write_nb(conn, sl_data, len + sizeof(struct dl_hdr))) < 0) {
		free(sl_data);
		return -12;
	}

	/* If the written data size is different than expected, return error */
	if (wlen != (len + sizeof(struct dl_hdr))) {
		free(sl_data);
		return -13;
	}

	/* Free packet memory */
	free(sl_data);

	return pkt->msg_size;
}

