CC=gcc
CPP=g++
CCFLAGS=-Wall -Werror -fPIC
INCLUDEDIRS=-I../../include

compile:
	${CC} ${INCLUDEDIRS} ${CCFLAGS} -c hsalsa20_core.c
	${CC} ${INCLUDEDIRS} ${CCFLAGS} -c salsa20_core.c
	${CC} ${INCLUDEDIRS} ${CCFLAGS} -c salsa20_xor.c
	${CC} ${INCLUDEDIRS} ${CCFLAGS} -c xsalsa20_xor.c

compile_cpp:
	${CPP} ${INCLUDEDIRS} ${CCFLAGS} -c hsalsa20_core.c
	${CPP} ${INCLUDEDIRS} ${CCFLAGS} -c salsa20_core.c
	${CPP} ${INCLUDEDIRS} ${CCFLAGS} -c salsa20_xor.c
	${CPP} ${INCLUDEDIRS} ${CCFLAGS} -c xsalsa20_xor.c

clean:
	rm -f *.o

