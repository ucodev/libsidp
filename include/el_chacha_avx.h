/**
 * @file el_chacha_avx.h
 * @brief Header to chacha_avx.c
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


#ifndef SIDP_EL_CHACHA_AVX_H
#define SIDP_EL_CHACHA_AVX_H

/* Prototypes */
int el_chacha_avx_init(void);
int el_chacha_avx_create_key(const unsigned char *key_data, unsigned char *key);
size_t el_chacha_avx_encrypt_output_len(size_t plain_data_len);
size_t el_chacha_avx_decrypt_output_len(size_t enc_data_len);
int el_chacha_avx_encrypt_data(
		const unsigned char *key,
		unsigned char *out,
		const unsigned char *in,
		size_t in_len);
int el_chacha_avx_decrypt_data(
		const unsigned char *key,
		unsigned char *out,
		const unsigned char *in,
		size_t in_len);

#endif

