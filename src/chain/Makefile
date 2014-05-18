MAKE=CC='${CC}' CCFLAGS='${CCFLAGS}' LDFLAGS='${LDFLAGS}' make

compile:
	${MAKE} -C incoming/
	${MAKE} -C outgoing/

clean:
	${MAKE} -C incoming/ clean
	${MAKE} -C outgoing/ clean

