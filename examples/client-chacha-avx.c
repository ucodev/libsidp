#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "net.h"
#include "sidp.h"


static void _usage(int argc, char **argv) {
	fprintf(stderr, "Usage: %s <user> <password> <data>\n", argv[0]);

	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
	int ret;
	sock_t fd;
	struct sidpconn conn;

	if (argc != 4)
		_usage(argc, argv);

	if ((fd = example_net_stream_connect("127.0.0.1", 6767)) < 0) {
		printf("Error #1.\n");
		return 1;
	}

	sidp_conn_init(&conn, fd, 10, 20, 1234, SIDP_CONN_TYPE_NORMAL);
	sidp_conn_set_support(&conn, SIDP_SUPPORT_ENCAP_DEFAULT_FL);
	sidp_conn_set_support(&conn, SIDP_SUPPORT_COMPRESS_LZO_FL);
	sidp_conn_set_support(&conn, SIDP_SUPPORT_CIPHER_CHACHA_AVX_FL);

	ret = sidp_seq_init_user(&conn);

	if (ret < 0) {
		printf("Error #2: %d\n", ret);
		sidp_conn_close(&conn);
		return 1;
	}

	ret = sidp_seq_auth_user(&conn, argv[1], (unsigned char *) argv[2]);

	if (ret < 0) {
		printf("Error #3: %d\n", ret);
		sidp_conn_close(&conn);
		return 1;
	}

	ret = sidp_seq_negotiation_user(&conn);

	if (ret < 0) {
		printf("Error #4: %d\n", ret);
		sidp_conn_close(&conn);
		return 1;
	}

	/* Key was already set on the authentication sequence.
	 * This is just an example of usage of sidp_conn_set_key().
	 * If you want to change the encryption key at the middle of the
	 * data sequence, you must use this function to do it on both sides
	 * of the connection.
	 */
	sidp_conn_set_key(&conn, (unsigned char *) argv[2]);

	ret = sidp_seq_data_send(&conn, argv[3], strlen(argv[3]) + 1);

	if (ret < 0) {
		printf("Error #5: %d\n", ret);
		sidp_conn_close(&conn);
		return 1;
	}

	sidp_conn_close(&conn);

	return 0;
}

