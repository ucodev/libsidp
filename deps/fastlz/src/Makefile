CC=gcc
CCFLAGS=-Wall -Werror -fPIC
INCLUDEDIRS=-I../include
LDFLAGS=-shared
TARGET=libfastlz.so

compile:
	${CC} ${INCLUDEDIRS} ${CCFLAGS} -c fastlz.c
	${CC} ${LDFLAGS} -o ${TARGET} *.o

install:
	cp ${TARGET} /usr/local/lib/

clean:
	rm -f ${TARGET}
	rm -f *.o

