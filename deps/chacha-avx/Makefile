
compile:
	make -C src/

compile_cpp:
	make -C src/ compile_cpp

install:
	cp src/*.so /usr/local/lib/
	mkdir -p /usr/local/include/chacha-avx
	cp include/*.h /usr/local/include/chacha-avx/

clean:
	make -C src/ clean

