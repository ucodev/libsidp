INCLUDE_DIRS=-I../../../include

compile:
	${CC} ${INCLUDE_DIRS} ${CCFLAGS} -c fastlz.c
	${CC} ${INCLUDE_DIRS} ${CCFLAGS} -c lzo.c
	${CC} ${INCLUDE_DIRS} ${CCFLAGS} -c zlib.c
	${CC} ${INCLUDE_DIRS} ${CCFLAGS} -c cl_api.c

clean:
	rm -f *.o
