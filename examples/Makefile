all:
	clang -DCOMPILE_POSIX=1 -I../include -Wall -g -c client.c
	clang -DCOMPILE_POSIX=1 -I../include -Wall -g -c client-chacha-avx.c
	clang -DCOMPILE_POSIX=1 -I../include -Wall -g -c client-chacha-avx2.c
	clang -DCOMPILE_POSIX=1 -I../include -Wall -g -c server.c
	clang -DCOMPILE_POSIX=1 -I../include -Wall -g -c server-chacha-avx.c
	clang -DCOMPILE_POSIX=1 -I../include -Wall -g -c server-chacha-avx2.c
	clang -DCOMPILE_POSIX=1 -Wall -g -c net.c
	clang -o client client.o net.o -lssl -lminilzo -lz -lnacl -lsidp -lfastlz -lchacha-avx -lchacha-avx2
	clang -o client-chacha-avx client-chacha-avx.o net.o -lssl -lminilzo -lz -lnacl -lsidp -lfastlz -lchacha-avx -lchacha-avx2
	clang -o client-chacha-avx2 client-chacha-avx2.o net.o -lssl -lminilzo -lz -lnacl -lsidp -lfastlz -lchacha-avx -lchacha-avx2
	clang -o server server.o net.o -lssl -lminilzo -lz -lnacl -lsidp -lfastlz -lchacha-avx -lchacha-avx2
	clang -o server-chacha-avx server-chacha-avx.o net.o -lssl -lminilzo -lz -lnacl -lsidp -lfastlz -lchacha-avx -lchacha-avx2
	clang -o server-chacha-avx2 server-chacha-avx2.o net.o -lssl -lminilzo -lz -lnacl -lsidp -lfastlz -lchacha-avx -lchacha-avx2

clean:
	rm -f *.o
	rm -f client client-chacha-avx client-chacha-avx2
	rm -f server server-chacha-avx server-chacha-avx2
