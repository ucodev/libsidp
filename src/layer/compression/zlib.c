/**
 * @file zlib.c
 * @brief SIDP Compression Layer - zlib Compress/Decompress Interface
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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <zlib.h>

#include "cl_zlib.h"

/**
 * @brief zlib initialization function.
 * Shall be called before any other cl_zlib_*() function.
 * @return 0 on success, -1 on failure
 */
int cl_zlib_init(void) {
	/* Initialize zlib library */
	return 0;
}

/**
 * @brief zlib compressed data length
 * @see cl_zlib_compress_data()
 * @param uncomp_len The size of uncompressed data
 * @return The required size for the 'out' param of the cl_zlib_compress_data()
 * function.
 */
size_t cl_zlib_compress_output_len(size_t uncomp_len) {
	return uncomp_len;
}

/**
 * @brief zlib compress data function
 * @see cl_zlib_compress_output_len()
 * @see cl_zlib_decompress_data()
 * @param out_data Output buffer containing the compressed data.
 * @param in_data Input buffer contataining the uncompressed data.
 * @param in_size The size of uncompressed data.
 * @return The size of compressed data or -1 on error.
 */
int cl_zlib_compress_data(
		void *out_data,
		const void *in_data,
		size_t in_size) {

	uint8_t status;
	size_t out_len;
	z_stream strm;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;

	if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) != Z_OK)
		return -1;

	strm.next_in = (unsigned char *) in_data;
	strm.avail_in = in_size;
	strm.avail_out = in_size;
	strm.next_out = ((unsigned char *) out_data) + 1;

	if (deflate(&strm, Z_FINISH) == Z_STREAM_ERROR) {
		deflateEnd(&strm);
		return -2;
	}

	deflateEnd(&strm);

	/* Compute out_len */
	out_len = in_size - strm.avail_out;

	/* Validate whether data was compressed or not */
	if (out_len >= in_size) {
		memcpy(((char *) out_data) + 1, in_data, in_size);
		out_len = in_size;
		status = 0;
	} else {
		status = 1;
	}

	/* Set compression status */
	((uint8_t *) out_data)[0] = status;

	return out_len + 1;
}

/**
 * @brief zlib decompress data function
 * @see cl_zlib_init()
 * @see cl_zlib_compress_data()
 * @param out_data Output buffer containing the decompressed data.
 * @param in_data Input buffer contataining the compressed data.
 * @param in_size The size of compressed data.
 * @return The size of decompressed data or -1 on error.
 */
int cl_zlib_decompress_data(
		void *out_data,
		size_t out_size,
		const void *in_data,
		size_t in_size) {

	z_stream strm;

	if (!((uint8_t *) in_data)[0]) {
		memcpy(out_data, ((const char *) in_data) + 1, in_size - 1);

		return in_size - 1;
	}

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = 0;
	strm.next_in = Z_NULL;

	if (inflateInit(&strm) != Z_OK)
		return -1;

	strm.avail_in = in_size - 1;
	strm.next_in = ((unsigned char *) in_data) + 1;
	strm.avail_out = out_size;
	strm.next_out = (Bytef *) out_data;

	if (inflate(&strm, Z_FINISH) == Z_STREAM_ERROR) {
		inflateEnd(&strm);
		return -2;
	}

	return out_size - strm.avail_out;
}

