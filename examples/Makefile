all:
	clang -DCOMPILE_POSIX=1 -I../include -Wall -g -c client.c
	clang -DCOMPILE_POSIX=1 -I../include -Wall -g -c client-chacha-avx2.c
	clang -DCOMPILE_POSIX=1 -I../include -Wall -g -c server.c
	clang -DCOMPILE_POSIX=1 -I../include -Wall -g -c server-chacha-avx2.c
	clang -DCOMPILE_POSIX=1 -Wall -g -c net.c
	clang -o client client.o net.o -lssl -lminilzo -lz -lnacl -lsidp -lfastlz -lchacha-avx2
	clang -o client-chacha-avx2 client.o net.o -lssl -lminilzo -lz -lnacl -lsidp -lfastlz -lchacha-avx2
	clang -o server server.o net.o -lssl -lminilzo -lz -lnacl -lsidp -lfastlz -lchacha-avx2
	clang -o server-chacha-avx2 server.o net.o -lssl -lminilzo -lz -lnacl -lsidp -lfastlz -lchacha-avx2

clean:
	rm -f *.o
	rm -f server client-chacha-avx2
	rm -f server server-chacha-avx2
