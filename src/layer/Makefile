MAKE=CC='${CC}' CCFLAGS='${CCFLAGS}' LDFLAGS='${LDFLAGS}' make

compile:
	${MAKE} -C compression/
	${MAKE} -C encryption/
	${MAKE} -C session/

clean:
	${MAKE} -C compression/ clean
	${MAKE} -C encryption/ clean
	${MAKE} -C session/ clean

