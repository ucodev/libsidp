INCLUDE_DIRS=-I../include 
OBJS=./chain/incoming/*.o ./chain/outgoing/*.o ./layer/session/*.o ./layer/encryption/*.o ./layer/compression/*.o ./sequence/data/*.o ./sequence/authentication/*.o ./sequence/negotiation/*.o ./sequence/init/*.o ./*.o
MAKE=CC='${CC}' CCFLAGS='${CCFLAGS}' LDFLAGS='${LDFLAGS}' make


compile:
	${CC} ${INCLUDE_DIRS} ${CCFLAGS} -c bitops.c
	${CC} ${INCLUDE_DIRS} ${CCFLAGS} -c skt.c
	${CC} ${INCLUDE_DIRS} ${CCFLAGS} -c sidp.c
	${MAKE} -C chain/
	${MAKE} -C layer/
	${MAKE} -C sequence/
	${CC} -o libsidp.so ${OBJS} ${LDFLAGS}

clean:
	${MAKE} -C chain/ clean
	${MAKE} -C layer/ clean
	${MAKE} -C sequence/ clean
	rm -f *.o
	rm -f *.so

install:
	cp libsidp.so /usr/local/lib/
	ldconfig || true
	mkdir -p /usr/local/include/sidp || true
	cp ../include/* /usr/local/include/sidp/

