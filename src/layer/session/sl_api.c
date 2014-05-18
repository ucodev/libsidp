/**
 * @file sl_api.c
 * @brief Session Layer - API
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

#include "sl_default.h"
#include "sl_api.h"

/**
 * @brief Session Layer interface initializer
 * @see SL_ENCAP_TYPE_DEFAULT
 * @see sl_data
 * @param sld A 'struct sl_data' to be initialized
 * @param encap_type The type of session encapsulation to be used
 * (e.g. default)
 * @return 0 on success, -1 on error.
 */
int sl_data_init(struct sl_data *sld, int encap_type) {
	memset(sld, 0, sizeof(struct sl_data));

	if (encap_type == SL_ENCAP_TYPE_DEFAULT) {
		sld->init = sl_default_init;
		sld->encap_output_len = sl_default_encap_output_len;
		sld->decap_output_len = sl_default_decap_output_len;
		sld->encap = (int (*) (void *, const void *, size_t, struct sl_hdr *)) sl_default_encap_data;
		sld->decap = (int (*) (void *, const void *, size_t, struct sl_hdr *)) sl_default_decap_data;

		return sld->init();
	}

	return -1;
}

