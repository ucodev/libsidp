/**
 * @file lzo.c
 * @brief SIDP Compression Layer - LZO Compress/Decompress Interface
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


/* TODO: Implement checksum verification */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef COMPILE_POSIX
#  ifdef USE_MINILZO
#    include <minilzo/minilzo.h>
#    define lzo_free free
#    define lzo_malloc malloc
#  else
#    include <lzo/lzoutil.h>
#    include <lzo/lzo1x.h>
#  endif
#elif defined(COMPILE_WIN32)
#  include <minilzo/minilzo.h>
#  define lzo_free free
#  define lzo_malloc malloc
#endif

#include "cl_lzo.h"

/**
 * @brief LZO initialization function.
 * Shall be called before any other cl_lzo_*() function.
 * @return 0 on success, -1 on failure
 */
int cl_lzo_init(void) {
	/* Initialize LZO library */
	return -(lzo_init() != LZO_E_OK);
}

/**
 * @brief LZO compressed data length
 * @see cl_lzo_compress_data()
 * @param uncomp_len The size of uncompressed data
 * @return The required size for the 'out' param of the cl_lzo_compress_data()
 * function.
 */
size_t cl_lzo_compress_output_len(size_t uncomp_len) {
	return uncomp_len + (uncomp_len / 16) + 64 + 3 + 1;
}

/**
 * @brief LZO compress data function
 * @see cl_lzo_compress_output_len()
 * @see cl_lzo_decompress_data()
 * @param out_data Output buffer containing the compressed data.
 * @param in_data Input buffer contataining the uncompressed data.
 * @param in_size The size of uncompressed data.
 * @return The size of compressed data or -1 on error.
 */
int cl_lzo_compress_data(
		void *out_data,
		const void *in_data,
		size_t in_size) {

	uint8_t status;
	lzo_bytep in = (lzo_bytep) in_data;
	lzo_voidp wmem;
	lzo_uint in_len = (lzo_uint) in_size;
	lzo_uint out_len;

	/* Memory allocations */
	if (!(wmem = lzo_malloc(LZO1X_1_MEM_COMPRESS)))
		return -1;

	/* Compress data */
	if (lzo1x_1_compress(in, in_len, ((unsigned char *) out_data) + 1, &out_len, wmem) != LZO_E_OK) {
		lzo_free(wmem);

		return -2;
	}

	/* Validate whether data was compressed or not */
	if (out_len >= in_len) {
		memcpy(((char *) out_data) + 1, in_data, in_size);
		out_len = in_size;
		status = 0;
	} else {
		status = 1;
	}

	/* Set compression status */
	((uint8_t *) out_data)[0] = status;

	/* Free memory */
	lzo_free(wmem);

	return out_len + 1;
}

/**
 * @brief LZO decompress data function
 * @see cl_lzo_init()
 * @see cl_lzo_compress_data()
 * @param out_data Output buffer containing the decompressed data.
 * @param in_data Input buffer contataining the compressed data.
 * @param in_size The size of compressed data.
 * @return The size of decompressed data or -1 on error.
 */
int cl_lzo_decompress_data(
		void *out_data,
		size_t out_size,
		const void *in_data,
		size_t in_size) {

	lzo_bytep in = (lzo_bytep) in_data;
	lzo_bytep out;
	lzo_uint in_len = (lzo_uint) in_size;
	lzo_uint out_len = out_size;

	/* Check if data is compressed */
	if (!((uint8_t *) in_data)[0]) {
		memcpy(out_data, in + 1, in_size - 1);

		return in_size - 1;
	}

	out = (lzo_bytep) out_data;

	/* Compress data */
	if (lzo1x_decompress_safe(in + 1, in_len - 1, out, &out_len, NULL) != LZO_E_OK)
		return -1;

	return out_len;
}

