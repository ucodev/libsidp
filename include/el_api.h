/**
 * @file el_api.h
 * @brief Header file for el_api.c
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


#ifndef EL_API_H
#define EL_API_H

#include <stdio.h>

/**
 * @def EL_CIPHER_TYPE_AES256
 * @brief AES-256 cipher type
 * @see el_data_init()
 */
#define EL_CIPHER_TYPE_AES256	1
/**
 * @def EL_CIPHER_TYPE_XSALSA20
 * @brief XSALSA20 cipher type
 * @see el_data_init()
 */
#define EL_CIPHER_TYPE_XSALSA20	2

/**
 * @struct el_data
 * @brief Data structure containing the abstraction of the Encryption Layer.
 * @see el_data_init()
 */
struct el_data {
	int (*init) (void);
	int (*create_key) (const unsigned char *, unsigned char *);
	size_t (*encrypt_output_len) (size_t);
	size_t (*decrypt_output_len) (size_t);
	int (*encrypt) (const unsigned char *, unsigned char *, const unsigned char *, size_t);
	int (*decrypt) (const unsigned char *, unsigned char *, const unsigned char *, size_t);
};

int el_data_init(struct el_data *eld, int cipher_type);

#endif

