/**
 * @file skt.c
 * @brief Abstract interface to read/write sockets (with non-blocking support)
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
#include <time.h>

#include "sidp.h"
#include "skt.h"

/**
 * @brief A wrapper to read() with non-blocking support
 */
int sidp_read_nb(struct sidpconn *conn, void *buf, size_t len) {
	int ret, offset;
	char *data = (char *) buf;

	for (ret = 0, offset = 0; ((unsigned int) offset) != len; ) {
		ret = sidp_read(conn->fd, data + offset, len - offset);

		if (ret < 0)
			return -1;

		conn->bytes_in += ret;
		conn->last_fd_read = time(NULL);

		if (!ret && (((unsigned int) offset) != len))
			return -1;

		offset += ret;
	}

	return offset;
}

/**
 * @brief A wrapper to write() with non-blocking support
 */
int sidp_write_nb(struct sidpconn *conn, const void *buf, size_t len) {
	int ret, offset;
	const char *data = (const char *) buf;

	for (ret = 0, offset = 0; ((unsigned int) offset) != len; ) {
		ret = sidp_write(conn->fd, data + offset, len - offset);

		if (ret < 0)
			return -1;

		conn->bytes_out += ret;
		conn->last_fd_write = time(NULL);

		if (!ret && (((unsigned int) offset) != len))
			return -1;

		offset += ret;
	}

	return offset;
}

