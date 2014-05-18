INCLUDE_DIRS=-I../../../include

compile:
	${CC} ${INCLUDE_DIRS} ${CCFLAGS} -c aes256cbc.c
	${CC} ${INCLUDE_DIRS} ${CCFLAGS} -c xsalsa20.c
	${CC} ${INCLUDE_DIRS} ${CCFLAGS} -c el_api.c

clean:
	rm -f *.o
