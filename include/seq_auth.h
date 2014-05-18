/**
 * @file seq_auth.h
 * @brief Header file to seq_auth.c
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


#ifndef SIDP_SEQ_AUTH_H
#define SIDP_SEQ_AUTH_H

#include <stdint.h>

#include "sidp.h"

/**
 * @struct srp_data
 * @brief SRP data exchange structure
 */
struct srp_data {
	char username[SIDP_USER_MAX_LEN + 1];
	unsigned char bytes_A[512];
	unsigned char bytes_s[16];
	unsigned char bytes_B[512];
	unsigned char bytes_M[32];
	unsigned char bytes_HAMK[32];
	uint16_t len_A;
	uint16_t len_s;
	uint16_t len_B;
	uint16_t len_M;
	uint16_t len_HAMK;
};

/* Prototypes */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_auth_user(
		struct sidpconn *conn,
		const char *user,
		const unsigned char *pass);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_auth_host(
		struct sidpconn *conn,
		const char *user,
		const unsigned char *pass);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_auth_host_c(
		struct sidpconn *conn,
		int (*get_password) (const char *, unsigned char *, size_t));

#endif
