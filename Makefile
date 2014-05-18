CC=clang
CPP=clang++
LDFLAGS=-shared
CCFLAGS=-DCOMPILE_POSIX=1 -DWITH_LZO_SUPPORT=1 -DUSE_MINILZO=1 -D_REENTRANT -fPIC -m64 -Werror -Wall -g
MAKE=CC='${CC}' CCFLAGS='${CCFLAGS}' LDFLAGS='${LDFLAGS}' make
MAKE_CPP=CC='${CPP}' CCFLAGS='${CCFLAGS}' LDFLAGS='${LDFLAGS}' make

compile:
	make -C deps/
	${MAKE} -C src/

compile_cpp:
	${MAKE_CPP} -C src/

clean:
	make -C deps/ clean
	${MAKE} -C src/ clean

install:
	${MAKE} -C src/ install

