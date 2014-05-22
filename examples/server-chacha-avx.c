#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "net.h"
#include "sidp.h"

static void _usage(int argc, char **argv) {
	fprintf(stderr, "Usage: %s <user> <password>\n", argv[0]);

	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
	int ret;
	sock_t fd, fd_acpt;
	uint32_t raddr;
	char buf[SIDP_PKT_MSG_MAX_LEN];
	size_t len;
	struct sidpconn conn;

	if (argc != 3)
		_usage(argc, argv);

	if ((fd = example_net_stream_listen(NULL, 6767, 10)) < 0) {
		printf("Error #1.\n");
		return 1;
	}

	for (;;) {
		if ((fd_acpt = example_net_stream_accept(fd, &raddr)) < 0) {
			printf("Error #2.\n");
			return 1;
		}

		sidp_conn_init(&conn, fd_acpt, 20, 0, 0, SIDP_CONN_TYPE_NORMAL);
		sidp_conn_set_support(&conn, SIDP_SUPPORT_ENCAP_DEFAULT_FL);
		sidp_conn_set_support(&conn, SIDP_SUPPORT_COMPRESS_LZO_FL);
		sidp_conn_set_support(&conn, SIDP_SUPPORT_CIPHER_CHACHA_AVX_FL);

		ret = sidp_seq_init_host(&conn);

		if (ret < 0) {
			printf("Error #3: %d\n", ret);
			sidp_conn_close(&conn);
			return 1;
		}

		printf("Connection from device: %d\n", conn.ddev);

		ret = sidp_seq_auth_host(&conn, argv[1], (unsigned char *) argv[2]);
		if (ret < 0) {
			printf("Error #3: %d\n", ret);
			sidp_conn_close(&conn);
			return 1;
		}

		ret = sidp_seq_negotiation_host(&conn);

		if (ret < 0) {
			printf("Error #4: %d\n", ret);
			sidp_conn_close(&conn);
			return 1;
		}

		/* Key was already set on the authentication sequence.
		 * This is just an example of usage of sidp_conn_set_key().
		 * If you want to change the encryption key at the middle of the
		 * data sequence, you must use this function to do it on both
		 * sides of the connection.
		 */
		sidp_conn_set_key(&conn, (unsigned char *) argv[2]);

		ret = sidp_seq_data_recv(&conn, buf, &len);

		if (ret < 0) {
			printf("Error #5: %d\n", ret);
			sidp_conn_close(&conn);
			return 1;
		}

		printf("buffer: %s\n", buf);

		sidp_conn_close(&conn);
	}

	return 0;
}
