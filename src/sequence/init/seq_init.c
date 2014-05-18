/**
 * @file seq_init.c
 * @brief SIDP - Init Sequence API
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
#include "seq_init.h"

/**
 * @brief Send an init sequence packet
 * @param conn SIDP connection descriptor
 * @param data Init data to be sent
 */
static int sidp_seq_init_pkt_send(
		struct sidpconn *conn,
		const struct init_data *data) {
	struct sidpopt opt;
	struct sidppkt pkt;

	/* Reset options and packet memory */
	memset(&pkt, 0, sizeof(struct sidppkt));
	memset(&opt, 0, sizeof(struct sidpopt));

	/* Set SIDP packet options */
	sidp_pkt_set_opt(&opt, SL_ENCAP_TYPE_DEFAULT, 0, 0, SIDP_MSG_TYPE_INIT, NULL);

	/* Create SIDP packet */
	pkt.sdev = conn->sdev;
	pkt.ddev = conn->ddev;
	pkt.sid = conn->sid;
	pkt.msg = (void *) data;
	pkt.msg_size = sizeof(struct init_data);

	/* Dispatch packet */
	if (sidp_pkt_send(conn, &pkt, &opt) < 0)
		return -1;

	return 0;
}

/**
 * @brief Receives an init sequence packet
 * @param conn SIDP connection descriptor
 * @param data Received init sequence data buffer
 */
static int sidp_seq_init_pkt_recv(
		struct sidpconn *conn,
		struct init_data *data) {
	struct sidpopt opt;
	struct sidppkt pkt;

	/* Reset data, options and packet memory */
	memset(data, 0, sizeof(struct init_data));
	memset(&pkt, 0, sizeof(struct sidppkt));
	memset(&opt, 0, sizeof(struct sidpopt));

	/* Receive packet */
	sidp_pkt_recv(conn, &pkt, &opt);

	/* Check if the received message type is different than
	 * SIDP_MSG_TYPE_INIT
	 */
	if (opt.msg_type != SIDP_MSG_TYPE_INIT)
		return -1;

	/* Grant that the length of the received data is the same as expected */
	if (pkt.msg_size != sizeof(struct init_data))
		return -2;

	/* Copy packet message to data buffer */
	memcpy(data, pkt.msg, pkt.msg_size);

	/* Free packet memory */
	free(pkt.msg);

	return 0;
}

/**
 * @brief Initializes user init sequence
 * @param conn SIDP connection descriptor
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_init_user(struct sidpconn *conn) {
	struct init_data init_data;

	/* Compose data to be sent */
	init_data.conn_type = htons(conn->type);
	init_data.sdev = htonl(conn->sdev);
	init_data.ddev = htonl(conn->ddev);
	init_data.sid = htonl(conn->sid);

	/* Send packet */
	if (sidp_seq_init_pkt_send(conn, &init_data) < 0)
		return -1;

	/* Receive packet */
	if (sidp_seq_init_pkt_recv(conn, &init_data) < 0)
		return -2;

	/* Validate data */
	if (conn->sid != ntohl(init_data.sid))
		return -3;

	/* Validate connection type and device id fields */
	if (conn->type == SIDP_CONN_TYPE_NORMAL) {
		if (conn->sdev != ntohl(init_data.ddev))
			return -4;

		if (conn->ddev != ntohl(init_data.sdev))
			return -5;
	} else if (conn->type == SIDP_CONN_TYPE_PERSISTENT) {
		if (conn->sdev != ntohl(init_data.ddev))
			return -6;

		if (conn->ddev != ntohl(init_data.sdev))
			return -7;
	} else if (conn->type == SIDP_CONN_TYPE_ROUTING) {
		if (conn->ddev != ntohl(init_data.ddev))
			return -8;

		if (conn->sdev != ntohl(init_data.sdev))
			return -9;
	} else {
		return -10;
	}

	/* Set connection to initiated */
	set_bit(&conn->status_flags, SIDP_INITIATED_FL);

	/* Everything is ok */
	return 0;
}

/**
 * @brief Initializes host init sequence
 * @param conn SIDP connection descriptor
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_init_host(struct sidpconn *conn) {
	struct init_data init_data;

	/* Receive packet */
	if (sidp_seq_init_pkt_recv(conn, &init_data) < 0)
		return -1;

	conn->type = ntohs(init_data.conn_type);
	conn->sid = ntohl(init_data.sid);

	/* Validate connection type and set device id fields */
	if (conn->type == SIDP_CONN_TYPE_NORMAL) {
		conn->ddev = ntohl(init_data.sdev);
	} else if (conn->type == SIDP_CONN_TYPE_PERSISTENT) {
		conn->ddev = ntohl(init_data.sdev);
	} else if (conn->type == SIDP_CONN_TYPE_ROUTING) {
		conn->ddev = ntohl(init_data.ddev);
		conn->sdev = ntohl(init_data.sdev);
	} else {
		return -2;
	}

	/* Reply for validation */
	init_data.sdev = htonl(conn->sdev);
	init_data.ddev = htonl(conn->ddev);
	init_data.sid = htonl(conn->sid);
	init_data.conn_type = htons(conn->type);

	/* Send packet back */
	if (sidp_seq_init_pkt_send(conn, &init_data) < 0)
		return -3;

	/* Set connection to initiated */
	set_bit(&conn->status_flags, SIDP_INITIATED_FL);

	return 0;
}

