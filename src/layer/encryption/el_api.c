/**
 * @file el_api.c
 * @brief Encryption Layer - API
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

#include "el_aes256cbc.h"
#if !defined(NO_XSALSA20)
#include "el_xsalsa20.h"
#endif
#include "el_api.h"

/**
 * @brief Encryption Layer interface initializer
 * @see EL_CIPHER_TYPE_AES256
 * @see EL_CIPHER_TYPE_XSALSA20
 * @see el_data
 * @param eld A 'struct el_data' to be initialized
 * @param cipher_type The type of cipher to be used (e.g. AES256, XSalsa20, etc)
 * @return 0 on success, -1 on error.
 */
int el_data_init(struct el_data *eld, int cipher_type) {
	memset(eld, 0, sizeof(struct el_data));

	if (cipher_type == EL_CIPHER_TYPE_AES256) {
		eld->init = el_aes256_init;
		eld->create_key = el_aes256_create_key;
		eld->encrypt_output_len = el_aes256_encrypt_output_len;
		eld->decrypt_output_len = el_aes256_decrypt_output_len;
		eld->encrypt = el_aes256_encrypt_data;
		eld->decrypt = el_aes256_decrypt_data;

		return eld->init();
#if !defined(NO_XSALSA20)
	} else if (cipher_type == EL_CIPHER_TYPE_XSALSA20) {
		eld->init = el_xsalsa20_init;
		eld->create_key = el_xsalsa20_create_key;
		eld->encrypt_output_len = el_xsalsa20_encrypt_output_len;
		eld->decrypt_output_len = el_xsalsa20_decrypt_output_len;
		eld->encrypt = el_xsalsa20_encrypt_data;
		eld->decrypt = el_xsalsa20_decrypt_data;

		return eld->init();
#endif
	}

	return -1;
}

