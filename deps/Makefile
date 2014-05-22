all:
	cd chacha-avx && ./do && cd ..
	cd chacha-avx2 && ./do && cd ..
	cd fastlz && ./do && cd ..
	cd minilzo && ./do && cd ..
	cd nacl && ./do && cd ..

clean:
	make -C chacha-avx/ clean
	make -C chacha-avx2/ clean
	make -C fastlz/ clean
	make -C minilzo/ clean
	make -C nacl/ clean

