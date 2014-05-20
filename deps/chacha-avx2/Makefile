
compile:
	make -C src/

compile_cpp:
	make -C src/ compile_cpp

install:
	cp src/*.so /usr/local/lib/
	mkdir -p /usr/local/include/chacha-avx2
	cp include/*.h /usr/local/include/chacha-avx2/

clean:
	make -C src/ clean

