/**
 * @file default.c
 * @brief SIDP - Default session encapsulation
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
#include <stdint.h>

#include "sl_default.h"

/**
 * @brief default session initialization function.
 * Shall be called before any other sl_default_*() function.
 * This function is automatically called by the sl_data_init() function.
 * @see sl_data_init()
 * @return 0 on success, -1 on failure
 */
int sl_default_init(void) {
	/* Initialize default session */
	return 0;
}

/**
 * @brief default session encapsulation data length
 * @see sl_default_decap_data()
 * @param in_len The size of unencapsulated data
 * @return The required size for the 'out' param of the sl_default_encap_data()
 * function.
 */
size_t sl_default_encap_output_len(size_t in_len) {
	return in_len + sizeof(struct sl_default_hdr);
}

/**
 * @brief default session decapsulation data length
 * @see sl_default_encap_data()
 * @param in_len The size of unencapsulated data
 * @return The required size for the 'out' param of the sl_default_decap_data()
 * function.
 */
size_t sl_default_decap_output_len(size_t in_len) {
	return in_len - sizeof(struct sl_default_hdr);
}

/**
 * @brief default session encapsulation data function
 * @see sl_default_encap_output_len()
 * @see sl_default_decap_data()
 * @param out Output buffer containing the encapsulated data.
 * @param in Input buffer contataining the unencapsulated data.
 * @param in_size The size of unencapsulated data.
 * @param hdr The header of the default session layer (read)
 * @return The size of encapsulated data or -1 on error.
 */
int sl_default_encap_data(
		void *out,
		void *in,
		size_t in_len,
		const struct sl_default_hdr *hdr) {
	memcpy(out, hdr, sizeof(struct sl_default_hdr));
	memcpy(((char *) out) + sizeof(struct sl_default_hdr), in, in_len);

	return sizeof(struct sl_default_hdr) + in_len;
}

/**
 * @brief default session decapsulation data function
 * @see sl_default_decap_output_len()
 * @see sl_default_encap_data()
 * @param out Output buffer containing the decapsulated data.
 * @param in Input buffer contataining the encapsulated data.
 * @param in_size The size of encapsulated data.
 * @param hdr The header of the default session layer (write)
 * @return The size of decapsulated data or -1 on error.
 */
int sl_default_decap_data(
		void *out,
		void *in,
		size_t in_len,
		struct sl_default_hdr *hdr) {
	memcpy(hdr, in, sizeof(struct sl_default_hdr));
	memcpy(out, ((char *) in) + sizeof(struct sl_default_hdr), in_len - sizeof(struct sl_default_hdr));

	return in_len - sizeof(struct sl_default_hdr);
}

