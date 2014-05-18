/**
 * @file cl_api.h
 * @brief Header file for cl_api.c
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


#ifndef CL_API_H
#define CL_API_H

/**
 * @def CL_CMPRESS_TYPE_LZO
 * @brief LZO compression type
 * @see cl_data_init()
 */
#define CL_COMPRESS_TYPE_LZO	1
/**
 * @def CL_COMPRESS_TYPE_ZLIB
 * @brief zlib compression type
 * @see cl_data_init()
 */
#define CL_COMPRESS_TYPE_ZLIB	2
/**
 * @def CL_COMPRESS_TYPE_FASTLZ
 * @breif FastLZ compression type
 * @see cl_data_init()
 */
#define CL_COMPRESS_TYPE_FASTLZ	3

/**
 * @struct cl_data
 * @brief Data structure containing the abstraction of the Compression Layer.
 * @see cl_data_init()
 */
struct cl_data {
	int (*init) (void);
	size_t (*compress_output_len) (size_t);
	int (*compress) (void *, const void *, size_t);
	int (*decompress) (void *, size_t, const void *, size_t);
};

int cl_data_init(struct cl_data *cld, int compress_type);

#endif

