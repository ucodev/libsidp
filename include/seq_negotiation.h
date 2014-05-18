/**
 * @file seq_negotiation.h
 * @brief Header file to seq_negotiation.c
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


#ifndef SIDP_SEQ_NEGOTIATION_H
#define SIDP_SEQ_NEGOTIATION_H

#include <stdint.h>

#include "sidp.h"

/**
 * @struct neg_data
 * @brief SIDP Negotiation Sequence data exchange structure
 */
struct neg_data {
	uint32_t flags;
};

/* Prototypes */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_negotiation_user(struct sidpconn *conn);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int sidp_seq_negotiation_host(struct sidpconn *conn);

#endif
