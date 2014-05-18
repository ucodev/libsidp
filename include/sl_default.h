/**
 * @file sl_default.h
 * @brief Header file for default.c
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


#ifndef SL_DEFAULT_H
#define SL_DEFAULT_H

#include <stdint.h>

/* structures */
/**
 * @struct sl_default_hdr
 * @brief Header structure for default session layer
 */
#ifdef COMPILE_WIN32
#pragma pack(push, 1)		// Alignment compatibility between MS and GNU compilers
#else
#pragma pack(push)
#pragma pack(1)
#endif
struct sl_default_hdr {
	uint32_t sdev;
	uint32_t ddev;
	uint32_t session_id;
	uint32_t reserved;
};
#pragma pack(pop)

/* Prototypees */
int sl_default_init(void);
size_t sl_default_encap_output_len(size_t in_len);
size_t sl_default_decap_output_len(size_t in_len);
int sl_default_encap_data(
		void *out,
		void *in,
		size_t in_len,
		const struct sl_default_hdr *in_hdr);
int sl_default_decap_data(
		void *out,
		void *in,
		size_t in_len,
		struct sl_default_hdr *out_hdr);

#endif

