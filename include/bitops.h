/**
 * @file bitops.h
 * @brief Header file to bitops.c
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


#ifndef SIDP_BITOPS_H
#define SIDP_BITOPS_H

#include <stdint.h>

#include "sidp.h"

/* Prototypes */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void set_bit(uint32_t *dword, unsigned int n);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void clear_bit(uint32_t *dword, unsigned int n);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void toggle_bit(uint32_t *dword, unsigned int n);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned int test_bit(const uint32_t *dword, unsigned int n);

#endif
