/**
 * @file cl_fastlz.h
 * @brief Header for fastlz.c file
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


#ifndef SIDP_CL_FASTLZ_H
#define SIDP_CL_FASTLZ_H

/* Prototypes */

int cl_fastlz_init(void);
size_t cl_fastlz_compress_output_len(size_t uncomp_len);
int cl_fastlz_compress_data(
		void *out_data,
		const void *in_data,
		size_t in_size);
int cl_fastlz_decompress_data(
		void *out_data,
		size_t out_size,
		const void *in_data,
		size_t in_size);

#endif

