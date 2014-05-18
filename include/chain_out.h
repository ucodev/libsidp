/**
 * @file chain_out.h
 * @brief Header file for chain_out.c
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


#ifndef SIDP_CHAIN_OUT_H
#define SIDP_CHAIN_OUT_H

#include "sidp.h"

#include "cl_api.h"
#include "el_api.h"
#include "sl_api.h"

/* Structures */
/**
 * @struct chain_out_data
 * @brief Data structure containing the layer processing functions.
 * @see chain_out_init()
 */
struct chain_out_data {
	struct cl_data cl;
	struct el_data el;
	struct sl_data sl;
};

/* Prototypes */
int chain_out_dispatch(
		struct sidpconn *conn,
		const struct sidppkt *pkt,
		const struct sidpopt *opt);

#endif
