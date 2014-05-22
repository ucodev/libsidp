CC=clang
CPP=clang++
CCFLAGS=-mavx -O3 -Wall -Werror -fPIC -c
LDFLAGS=-shared -s
TARGET=libchacha-avx.so
TARGET_CPP=libchacha-avx++.so

compile:
	${CC} ${CCFLAGS} *.c
	${CC} ${LDFLAGS} -o ${TARGET} *.o

compile_cpp:
	${CPP} ${CCFLAGS} *.c
	${CPP} ${LDFLAGS} -o ${TARGET_CPP} *.o

install:
	cp *.so /usr/local/lib/
	mkdir -p /usr/local/include/chacha-avx
	cp *.h /usr/local/include/chacha-avx

clean:
	rm -f *.o
	rm -f *.so

