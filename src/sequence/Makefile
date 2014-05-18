MAKE=CC='${CC}' CCFLAGS='${CCFLAGS}' LDFLAGS='${LDFLAGS}' make

compile:
	${MAKE} -C negotiation/
	${MAKE} -C authentication/
	${MAKE} -C data/
	${MAKE} -C init/

clean:
	${MAKE} -C negotiation/ clean
	${MAKE} -C authentication/ clean
	${MAKE} -C data/ clean
	${MAKE} -C init/ clean

