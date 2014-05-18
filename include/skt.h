/**
 * @file skt.h
 * @brief Header file to skt.c
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


#ifndef SIDP_SKT_H
#define SIDP_SKT_H

#include <time.h>

#include "sidp.h"

#ifdef COMPILE_POSIX
#include <unistd.h>
#elif defined(COMPILE_WIN32)
#include <windows.h>
#endif

/* Macros */
#ifdef COMPILE_POSIX
#define sidp_read(fd, buf, len) read(fd, buf, len)
#define sidp_write(fd, buf, len) write(fd, buf, len)
#elif defined(COMPILE_WIN32)
#define sidp_read(fd, buf, len) recv(fd, buf, len, 0)
#define sidp_write(fd, buf, len) send(fd, buf, len, 0)
#endif

/* Prototypes */
int sidp_read_nb(struct sidpconn *conn, void *buf, size_t len);
int sidp_write_nb(struct sidpconn *conn, const void *buf, size_t len);

#endif
