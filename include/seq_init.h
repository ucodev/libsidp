/**
 * @file seq_init.h
 * @brief Header file to seq_init.c
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


#ifndef SIDP_SEQ_INIT_H
#define SIDP_SEQ_INIT_H

#include <stdint.h>

#include "sidp.h"

/**
 * @struct init_data
 * @brief SIDP Init Sequence data exchange structure
 */
struct init_data {
	uint32_t sdev;
	uint32_t ddev;
	uint32_t sid;
	uint16_t conn_type;
};

/* Prototypes */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_init_user(struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_init_host(struct sidpconn *conn);

#endif

