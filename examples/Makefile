all:
	clang -DCOMPILE_POSIX=1 -I../include -Wall -g -c client.c
	clang -DCOMPILE_POSIX=1 -I../include -Wall -g -c server.c
	clang -DCOMPILE_POSIX=1 -Wall -g -c net.c
	clang -o client client.o net.o -lssl -lminilzo -lz -lnacl -lsidp -lfastlz
	clang -o server server.o net.o -lssl -lminilzo -lz -lnacl -lsidp -lfastlz

clean:
	rm -f *.o
	rm -f client
	rm -f server
