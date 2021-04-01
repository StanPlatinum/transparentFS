all:
	make -C mbedtls-adapter
	make -C pf-util

install:
	mkdir lib
	mv pf-util/libsgx_util.so lib
	mv mbedtls-adapter/crypto/mbedtls/install/lib/libmbedcrypto.so lib