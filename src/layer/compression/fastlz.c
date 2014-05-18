/**
 * @file fastlz.c
 * @brief SIDP Compression Layer - FastLZ Compress/Decompress Interface
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

#include <fastlz/fastlz.h>

#include "cl_fastlz.h"

/**
 * @brief FastLZ initialization function.
 * Shall be called before any other cl_fastlz_*() function.
 * @return 0 on success, -1 on failure
 */
int cl_fastlz_init(void) {
	/* Initialize LZO library */
	return 0;
}

/**
 * @brief FastLZ compressed data length
 * @see cl_fastlz_compress_data()
 * @param uncomp_len The size of uncompressed data
 * @return The required size for the 'out' param of the
 * cl_fastlz_compress_data() function.
 */
size_t cl_fastlz_compress_output_len(size_t uncomp_len) {
	return uncomp_len + (uncomp_len / 16) + 64 + 3 + 1;
}

/**
 * @brief FastLZ compress data function
 * @see cl_fastlz_compress_output_len()
 * @see cl_fastlz_decompress_data()
 * @param out_data Output buffer containing the compressed data.
 * @param in_data Input buffer contataining the uncompressed data.
 * @param in_size The size of uncompressed data.
 * @return The size of compressed data or -1 on error.
 */
int cl_fastlz_compress_data(
		void *out_data,
		const void *in_data,
		size_t in_size) {

	uint8_t status;
	int out_len;

	/* Compress data */
	if ((out_len = fastlz_compress(in_data, in_size, ((unsigned char *) out_data) + 1)) < 0)
		return -1;

	/* Validate whether data was compressed or not */
	if (out_len >= (signed) in_size) {
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
 * @brief FastLZ decompress data function
 * @see cl_fastlz_init()
 * @see cl_fastlz_compress_data()
 * @param out_data Output buffer containing the decompressed data.
 * @param in_data Input buffer contataining the compressed data.
 * @param in_size The size of compressed data.
 * @return The size of decompressed data or -1 on error.
 */
int cl_fastlz_decompress_data(
		void *out_data,
		size_t out_size,
		const void *in_data,
		size_t in_size) {

	int out_len;

	/* Check if data is compressed */
	if (!((uint8_t *) in_data)[0]) {
		memcpy(out_data, ((char *) in_data) + 1, in_size - 1);

		return in_size - 1;
	}

	/* Compress data */
	if ((out_len = fastlz_decompress(((char *) in_data) + 1, in_size - 1, out_data, out_size)) < 0)
		return -1;

	return out_len;
}

