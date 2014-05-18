CC=gcc
CPP=g++
CCFLAGS=-Wall -Werror -fPIC
INCLUDEDIRS=-I../../include

compile:
	${CC} ${INCLUDEDIRS} ${CCFLAGS} -c poly1305_auth.c
	${CC} ${INCLUDEDIRS} ${CCFLAGS} -c poly1305_verify.c
	${CC} ${INCLUDEDIRS} ${CCFLAGS} -c verify_16.c

compile_cpp:
	${CPP} ${INCLUDEDIRS} ${CCFLAGS} -c poly1305_auth.c
	${CPP} ${INCLUDEDIRS} ${CCFLAGS} -c poly1305_verify.c
	${CPP} ${INCLUDEDIRS} ${CCFLAGS} -c verify_16.c

clean:
	rm -f *.o

