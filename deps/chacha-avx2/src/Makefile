CC=clang
CPP=clang++
CCFLAGS=-DMANUAL_SCHEDULING -mavx2 -O3 -Wall -Werror -fPIC -c
LDFLAGS=-shared -s
TARGET=libchacha-avx2.so
TARGET_CPP=libchacha-avx2++.so

compile:
	${CC} ${CCFLAGS} *.c
	${CC} ${LDFLAGS} -o ${TARGET} *.o

compile_cpp:
	${CPP} ${CCFLAGS} *.c
	${CPP} ${LDFLAGS} -o ${TARGET_CPP} *.o

install:
	cp *.so /usr/local/lib/
	mkdir -p /usr/local/include/chacha-avx2
	cp *.h /usr/local/include/chacha-avx2

clean:
	rm -f *.o
	rm -f *.so

