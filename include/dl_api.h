/**
 * @file dl_api.h
 * @brief Header file contaning Description Layer header.
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


#ifndef DL_API_H
#define DL_API_H

#include <stdint.h>

/**
 * @struct dl_hdr
 * @brief Structure containing the Description Layer header.
 */
#ifdef COMPILE_WIN32
#pragma pack(push, 1)		// Alignment compatibility between MS and GNU compilers
#else
#pragma pack(push)
#pragma pack(1)
#endif
struct dl_hdr {
	uint32_t def_size;
	uint32_t inf_size;
	uint16_t session_type;
	uint16_t cipher_type;
	uint16_t compress_type;
	uint16_t msg_type;
	uint32_t reserved;
};
#pragma pack(pop)

#endif

