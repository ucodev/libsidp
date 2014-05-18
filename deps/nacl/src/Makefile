CC=gcc
CPP=g++
LDFLAGS=-shared
TARGET=libnacl.so
TARGET_CPP=libnacl++.so

compile:
	make -C poly1305/
	make -C xsalsa20/
	${CC} ${LDFLAGS} -o ${TARGET} poly1305/*.o xsalsa20/*.o

compile_cpp:
	make -C poly1305/ compile_cpp
	make -C xsalsa20/ compile_cpp
	${CPP} ${LDFLAGS} -o ${TARGET_CPP} poly1305/*.o xsalsa20/*.o

install:
	cp *.so /usr/local/lib/
	mkdir -p /usr/local/include/nacl
	cp ../include/* /usr/local/include/nacl/

clean:
	make -C poly1305/ clean
	make -C xsalsa20/ clean
	rm -f *.so

