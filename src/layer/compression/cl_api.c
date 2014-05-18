/**
 * @file cl_api.c
 * @brief Compression Layer - API
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
#include <string.h>

#ifdef WITH_LZO_SUPPORT
#include "cl_lzo.h"
#endif
#include "cl_fastlz.h"
#ifndef COMPILE_WIN32
#include "cl_zlib.h"
#endif
#include "cl_api.h"

/**
 * @brief Compression Layer interface initializer
 * @see CL_COMPRESS_TYPE_LZO
 * @see CL_COMPRESS_TYPE_ZLIB
 * @see cl_data
 * @param cld A 'struct cl_data' to be initialized
 * @param compress_type The type of compression to be used
 * (e.g. LZO, Zlib, etc)
 * @return 0 on success, -1 on error.
 */
int cl_data_init(struct cl_data *cld, int compress_type) {
	memset(cld, 0, sizeof(struct cl_data));

	if (compress_type == CL_COMPRESS_TYPE_FASTLZ) {
		cld->init = cl_fastlz_init;
		cld->compress_output_len = cl_fastlz_compress_output_len;
		cld->compress = cl_fastlz_compress_data;
		cld->decompress = cl_fastlz_decompress_data;

		return cld->init();
#ifdef WITH_LZO_SUPPORT
	} else if (compress_type == CL_COMPRESS_TYPE_LZO) {
		cld->init = cl_lzo_init;
		cld->compress_output_len = cl_lzo_compress_output_len;
		cld->compress = cl_lzo_compress_data;
		cld->decompress = cl_lzo_decompress_data;

		return cld->init();
#endif
#ifndef COMPILE_WIN32
	} else if (compress_type == CL_COMPRESS_TYPE_ZLIB) {
		cld->init = cl_zlib_init;
		cld->compress_output_len = cl_zlib_compress_output_len;
		cld->compress = cl_zlib_compress_data;
		cld->decompress = cl_zlib_decompress_data;

		return cld->init();
#endif
	}

	return -1;
}

