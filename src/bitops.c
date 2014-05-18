/**
 * @file bitops.c
 * @brief Flags field bit operations
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


#include <stdint.h>

#include "sidp.h"

/**
 * @brief Sets the 'n'th bit on 'dword'
 * @param dword A 32bit flags field
 * @param bit The bit number to be set
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void set_bit(uint32_t *dword, unsigned int n) {
	*dword |= (1 << n);
}

/**
 * @brief Clears the 'n'th bit on 'dword'
 * @param dword A 32bit flags field
 * @param bit The bit number to be cleared
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void clear_bit(uint32_t *dword, unsigned int n) {
	*dword &= ~(1 << n);
}

/**
 * @brief Toggles the 'n'th bit on 'dword'
 * @param dword A 32bit flags field
 * @param bit The bit number to be toggled
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void toggle_bit(uint32_t *dword, unsigned int n) {
	*dword ^= (1 << n);
}

/**
 * @brief Tests the 'n'th bit on 'dword'
 * @param dword A 32bit flags field
 * @param bit The bit number to be tested
 * @return 1 if the bit is set, 0 if it isn't
 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned int test_bit(const uint32_t *dword, unsigned int n) {
	return (*dword & (1 << n));
}

