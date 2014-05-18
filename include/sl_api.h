/**
 * @file sl_api.h
 * @brief Header file for sl_api.c
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


#ifndef SL_API_H
#define SL_API_H

#include <stdio.h>

#include "sl_default.h"

/**
 * @def SL_ENCAP_TYPE_DEFAULT
 * @brief Default session encapsulation type
 * @see sl_data_init()
 */
#define SL_ENCAP_TYPE_DEFAULT	1

/**
 * @struct sl_hdr
 * @brief Union data structure containing the header abstraction of Session
 * Layer packets
 */
#ifdef COMPILE_WIN32
#pragma pack(push, 1)		// Alignment compatibility between MS and GNU compilers
#else
#pragma pack(push)
#pragma pack(1)
#endif
struct sl_hdr {
	union {
		/* declare the available headers here */
		struct sl_default_hdr default_hdr;
	};
};
#pragma pack(pop)

/**
 * @struct sl_data
 * @brief Data structure containing the abstraction of the Session Layer.
 * @see sl_data_init()
 */
struct sl_data {
	int (*init) (void);
	size_t (*encap_output_len) (size_t);
	size_t (*decap_output_len) (size_t);
	int (*encap) (void *, const void *, size_t, struct sl_hdr *);
	int (*decap) (void *, const void *, size_t, struct sl_hdr *);
};

int sl_data_init(struct sl_data *sld, int encap_type);

#endif

