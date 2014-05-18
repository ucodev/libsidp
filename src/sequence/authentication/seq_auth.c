/**
 * @file seq_auth.c
 * @brief SIDP - Authentication Sequence API
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
#include <stdint.h>

#ifdef COMPILE_POSIX
#include <arpa/inet.h>
#elif defined(COMPILE_WIN32)
#include <windows.h>
#include <winsock2.h>
#endif

#include "sidp.h"
#include "bitops.h"
#include "srp.h"
#include "seq_auth.h"

/**
 * @brief Send an authentication sequence packet with SRP data
 * @param conn SIDP connection descriptor
 * @param data SRP data to be sent
 */
static int sidp_srp_pkt_send(
		struct sidpconn *conn,
		const struct srp_data *data) {
	struct sidpopt opt;
	struct sidppkt pkt;

	/* Reset packet and options memory */
	memset(&pkt, 0, sizeof(struct sidppkt));
	memset(&opt, 0, sizeof(struct sidpopt));

	/* Set SIDP packet options */
	sidp_pkt_set_opt(&opt, SL_ENCAP_TYPE_DEFAULT, 0, 0, SIDP_MSG_TYPE_AUTH, NULL);

	/* Create SIDP packet */
	pkt.sdev = conn->sdev;
	pkt.ddev = conn->ddev;
	pkt.sid = conn->sid;
	pkt.msg = (void *) data;
	pkt.msg_size = sizeof(struct srp_data);

	/* Dispatch packet */
	if (sidp_pkt_send(conn, &pkt, &opt) < 0)
		return -1;

	return 0;
}

/**
 * @brief Receives an authentication sequence packet with SRP data
 * @param conn SIDP connection descriptor
 * @param data SRP data received
 */
static int sidp_srp_pkt_recv(
		struct sidpconn *conn,
		struct srp_data *data) {
	struct sidpopt opt;
	struct sidppkt pkt;

	/* Reset data, options and packet memory */
	memset(data, 0, sizeof(struct srp_data));
	memset(&pkt, 0, sizeof(struct sidppkt));
	memset(&opt, 0, sizeof(struct sidpopt));

	/* Receive packet */
	if (sidp_pkt_recv(conn, &pkt, &opt) < 0)
		return -1;

	/* Check if the received message type is different than
	 * SIDP_MSG_TYPE_AUTH
	 */
	if (opt.msg_type != SIDP_MSG_TYPE_AUTH)
		return -2;

	/* Grant that the length of the received data is the same as expected */
	if (pkt.msg_size != sizeof(struct srp_data))
		return -3;

	/* Copy packet message to data buffer */
	memcpy(data, pkt.msg, pkt.msg_size);

	/* Free packet memory */
	free(pkt.msg);

	return 0;
}

/**
 * @brief Initializes user authentication sequence
 * @param conn SIDP connection descriptor
 * @param user User name
 * @param pass Password
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_auth_user(
		struct sidpconn *conn,
		const char *user,
		const unsigned char *pass) {
	struct SRPUser *usr;
	struct srp_data srp_data;

	const unsigned char *bytes_s = NULL;
	const unsigned char *bytes_v = NULL;
	const unsigned char *bytes_A = NULL;
	const unsigned char *bytes_M = NULL;

	int len_s = 0;
	int len_v = 0;
	int len_A = 0;
	int len_M = 0;

	const char *auth_username = NULL;

	SRP_HashAlgorithm alg = SRP_SHA1;
	SRP_NGType ng_type = SRP_NG_2048;

	/* Check if the connection is initiated */
	if (!test_bit(&conn->status_flags, SIDP_INITIATED_FL))
		return -1;

	/* Set connection username */
	strncpy(conn->user, user, strlen(user) >= sizeof(conn->user) ? sizeof(conn->user) - 1 : strlen(user));

	/* Set connection key */
	strncpy((char *) conn->key, (char *) pass, strlen((char *) pass) >= sizeof(conn->key) ? sizeof(conn->key) - 1 : strlen((char *) pass));

	/* Create a salted verification key */
	srp_create_salted_verification_key(alg, ng_type, user, pass, strlen((const char *) pass), &bytes_s, &len_s, &bytes_v, &len_v, NULL, NULL);

	/* Create a SRP user */
	usr = srp_user_new(alg, ng_type, user, pass, strlen((const char *) pass), NULL, NULL);

	/* Start user authentication */
	srp_user_start_authentication(usr, &auth_username, &bytes_A, &len_A);

	/* SEND to Host: username, bytes_A */
	memset(&srp_data, 0, sizeof(srp_data));
	memcpy(srp_data.username, user, strlen(user) >= sizeof(srp_data.username) ? sizeof(srp_data.username) - 1 : strlen(user));
	memcpy(srp_data.bytes_A, bytes_A, ((unsigned int) len_A) >= sizeof(srp_data.bytes_A) ? sizeof(srp_data.bytes_A) - 1 : len_A);
	srp_data.len_A = htons(((unsigned int) len_A) >= sizeof(srp_data.bytes_A) ? sizeof(srp_data.bytes_A) - 1 : len_A);

	if (sidp_srp_pkt_send(conn, &srp_data) < 0) {
		srp_user_delete(usr);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -2;
	}

	/* RECV from Host: bytes_s, bytes_B */
	if (sidp_srp_pkt_recv(conn, &srp_data) < 0) {
		srp_user_delete(usr);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -3;
	}

	/* User SRP-6a safety check */
	srp_user_process_challenge(usr, srp_data.bytes_s, ntohs(srp_data.len_s), srp_data.bytes_B, ntohs(srp_data.len_B), &bytes_M, &len_M);

	if (!bytes_M) {
		srp_user_delete(usr);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -4; /* Safety check violated */
	}

	/* SEND to Host: bytes_M */
	memset(&srp_data, 0, sizeof(srp_data));
	memcpy(srp_data.bytes_M, bytes_M, ((unsigned int) len_M) >= sizeof(srp_data.bytes_M) ? sizeof(srp_data.bytes_M) - 1 : len_M);
	srp_data.len_M = htons(((unsigned int) len_M) >= sizeof(srp_data.bytes_M) ? sizeof(srp_data.bytes_M) - 1 : len_M);

	if (sidp_srp_pkt_send(conn, &srp_data) < 0) {
		srp_user_delete(usr);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -5;
	}

	/* RECV from Host: bytes_HAMK */
	if (sidp_srp_pkt_recv(conn, &srp_data) < 0) {
		srp_user_delete(usr);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -6;
	}

	/* User session verification */
	srp_user_verify_session(usr, srp_data.bytes_HAMK);

	/* Verify authentication */
	if (!srp_user_is_authenticated(usr)) {
		srp_user_delete(usr);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -7; /* Authentication failed */
	}

	/* Set connection status to authenticated */
	set_bit(&conn->status_flags, SIDP_AUTHENTICATED_FL);

	return 0;	/* Authentication successful */
}

/**
 * @brief Initializes host authentication sequence
 * @param conn SIDP connection descriptor
 * @param user Expected User name
 * @param pass Password
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_auth_host(
		struct sidpconn *conn,
		const char *user,
		const unsigned char *pass) {
	struct SRPVerifier *ver;
	struct srp_data srp_data;

	const unsigned char *bytes_s = NULL;
	const unsigned char *bytes_v = NULL;
	const unsigned char *bytes_B = NULL;
	const unsigned char *bytes_HAMK = NULL;

	int len_s = 0;
	int len_v = 0;
	int len_B = 0;
	int len_M = 0;

	SRP_HashAlgorithm alg = SRP_SHA1;
	SRP_NGType ng_type = SRP_NG_2048;

	/* Check if the connection is initiated */
	if (!test_bit(&conn->status_flags, SIDP_INITIATED_FL))
		return -1;

	/* Set connection username */
	strncpy(conn->user, user, strlen(user) >= sizeof(conn->user) ? sizeof(conn->user) - 1 : strlen(user));

	/* Set connection key */
	strncpy((char *) conn->key, (char *) pass, strlen((char *) pass) >= sizeof(conn->key) ? sizeof(conn->key) - 1 : strlen((char *) pass));

	/* Create a salted verification key */
	srp_create_salted_verification_key(alg, ng_type, user, pass, strlen((const char *) pass), &bytes_s, &len_s, &bytes_v, &len_v, NULL, NULL);

	/* RECV From User: username, bytes_A */
	if (sidp_srp_pkt_recv(conn, &srp_data) < 0) {
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -2;
	}

	/* Create a SRP verifier */
	ver = srp_verifier_new(alg, ng_type, srp_data.username, bytes_s, len_s, bytes_v, len_v, srp_data.bytes_A, ntohs(srp_data.len_A), &bytes_B, &len_B, NULL, NULL);

	/* Verifier - SRP-6a Safety check */
	if (!bytes_B) {
		srp_verifier_delete(ver);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -3; /* Safety check violated */
	}

	/* SEND To User: bytes_s, bytes_B */
	memset(&srp_data, 0, sizeof(srp_data));
	memcpy(srp_data.bytes_s, bytes_s, ((unsigned int) len_s) >= sizeof(srp_data.bytes_s) ? sizeof(srp_data.bytes_s) - 1 : len_s);
	memcpy(srp_data.bytes_B, bytes_B, ((unsigned int) len_B) >= sizeof(srp_data.bytes_B) ? sizeof(srp_data.bytes_B) - 1 : len_B);
	srp_data.len_s = htons(((unsigned int) len_s) >= sizeof(srp_data.bytes_s) ? sizeof(srp_data.bytes_s) - 1 : len_s);
	srp_data.len_B = htons(((unsigned int) len_B) >= sizeof(srp_data.bytes_B) ? sizeof(srp_data.bytes_B) - 1 : len_B);

	if (sidp_srp_pkt_send(conn, &srp_data) < 0) {
		srp_verifier_delete(ver);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -4;
	}

	/* RECV From User: bytes_M */
	if (sidp_srp_pkt_recv(conn, &srp_data) < 0) {
		srp_verifier_delete(ver);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -5;
	}

	len_M = ntohs(srp_data.len_M);

	/* Verify authentication */
	srp_verifier_verify_session(ver, srp_data.bytes_M, &bytes_HAMK);

	if (!bytes_HAMK) {
		srp_verifier_delete(ver);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -6; /* Authentication failed */
	}

	/* SEND to User: bytes_HAMK */
	memset(&srp_data, 0, sizeof(srp_data));
	memcpy(srp_data.bytes_HAMK, bytes_HAMK, ((unsigned int) len_M) >= sizeof(srp_data.bytes_HAMK) ? sizeof(srp_data.bytes_HAMK) - 1 : len_M);
	srp_data.len_HAMK = htons(((unsigned int) len_M) >= sizeof(srp_data.bytes_HAMK) ? sizeof(srp_data.bytes_HAMK) - 1 : len_M);

	if (sidp_srp_pkt_send(conn, &srp_data) < 0) {
		srp_verifier_delete(ver);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -7;
	}

	/* Set connection status to authenticated */
	set_bit(&conn->status_flags, SIDP_AUTHENTICATED_FL);

	return 0; /* Authentication successful */
}

/**
 * @brief Initializes host authentication sequence
 * @param conn SIDP connection descriptor
 * @param user Expected User name
 * @param get_password A function pointer to a function that gets the user
 * password.
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_auth_host_c(
		struct sidpconn *conn,
		int (*get_password) (const char *, unsigned char *, size_t)) {
	unsigned char pass[SIDP_KEY_MAX_LEN + 1];
	struct SRPVerifier *ver;
	struct srp_data srp_data;

	const unsigned char *bytes_s = NULL;
	const unsigned char *bytes_v = NULL;
	const unsigned char *bytes_B = NULL;
	const unsigned char *bytes_HAMK = NULL;

	int len_s = 0;
	int len_v = 0;
	int len_B = 0;
	int len_M = 0;

	SRP_HashAlgorithm alg = SRP_SHA1;
	SRP_NGType ng_type = SRP_NG_2048;

	/* Check if the connection is initiated */
	if (!test_bit(&conn->status_flags, SIDP_INITIATED_FL))
		return -1;

	/* RECV From User: username, bytes_A */
	if (sidp_srp_pkt_recv(conn, &srp_data) < 0)
		return -2;

	/* Get user password */
	if (get_password(srp_data.username, pass, sizeof(pass) - 1) < 0)
		return -3;

	/* Ensure null termination for safe strlen() usage */
	pass[sizeof(pass) - 1] = 0;
	srp_data.username[sizeof(srp_data.username) - 1] = 0;

	/* Set connection username */
	strncpy(conn->user, srp_data.username, strlen(srp_data.username) >= sizeof(conn->user) ? sizeof(conn->user) - 1 : strlen(srp_data.username));

	/* Set connection key */
	strncpy((char *) conn->key, (char *) pass, strlen((char *) pass) >= sizeof(conn->key) ? sizeof(conn->key) - 1 : strlen((char *) pass));

	/* Create a salted verification key */
	srp_create_salted_verification_key(alg, ng_type, conn->user, pass, strlen((const char *) pass), &bytes_s, &len_s, &bytes_v, &len_v, NULL, NULL);

	/* Create a SRP verifier */
	ver = srp_verifier_new(alg, ng_type, conn->user, bytes_s, len_s, bytes_v, len_v, srp_data.bytes_A, ntohs(srp_data.len_A), &bytes_B, &len_B, NULL, NULL);

	/* Verifier - SRP-6a Safety check */
	if (!bytes_B) {
		srp_verifier_delete(ver);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -4; /* Safety check violated */
	}

	/* SEND To User: bytes_s, bytes_B */
	memset(&srp_data, 0, sizeof(srp_data));
	memcpy(srp_data.bytes_s, bytes_s, ((unsigned int) len_s) >= sizeof(srp_data.bytes_s) ? sizeof(srp_data.bytes_s) - 1 : len_s);
	memcpy(srp_data.bytes_B, bytes_B, ((unsigned int) len_B) >= sizeof(srp_data.bytes_B) ? sizeof(srp_data.bytes_B) - 1 : len_B);
	srp_data.len_s = htons(((unsigned int) len_s) >= sizeof(srp_data.bytes_s) ? sizeof(srp_data.bytes_s) - 1 : len_s);
	srp_data.len_B = htons(((unsigned int) len_B) >= sizeof(srp_data.bytes_B) ? sizeof(srp_data.bytes_B) - 1 : len_B);

	if (sidp_srp_pkt_send(conn, &srp_data) < 0) {
		srp_verifier_delete(ver);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -5;
	}

	/* RECV From User: bytes_M */
	if (sidp_srp_pkt_recv(conn, &srp_data) < 0) {
		srp_verifier_delete(ver);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -6;
	}

	len_M = ntohs(srp_data.len_M);

	/* Verify authentication */
	srp_verifier_verify_session(ver, srp_data.bytes_M, &bytes_HAMK);

	if (!bytes_HAMK) {
		srp_verifier_delete(ver);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -7; /* Authentication failed */
	}

	/* SEND to User: bytes_HAMK */
	/* NOTE:  srp_data.bytes_HAMK size shall be no greater than bytes_HAMK.
	 *	  If it exceeds, a memory access violation may exist.
	 */
	memset(&srp_data, 0, sizeof(srp_data));
	memcpy(srp_data.bytes_HAMK, bytes_HAMK, ((unsigned int) len_M) >= sizeof(srp_data.bytes_HAMK) ? sizeof(srp_data.bytes_HAMK) - 1 : len_M);
	srp_data.len_HAMK = htons(((unsigned int) len_M) >= sizeof(srp_data.bytes_HAMK) ? sizeof(srp_data.bytes_HAMK) - 1 : len_M);

	if (sidp_srp_pkt_send(conn, &srp_data) < 0) {
		srp_verifier_delete(ver);
		free((void *) bytes_s);
		free((void *) bytes_v);

		return -8;
	}

	/* Set connection status to authenticated */
	set_bit(&conn->status_flags, SIDP_AUTHENTICATED_FL);

	return 0; /* Authentication successful */
}

