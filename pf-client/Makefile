GRAPHENE_DIR = /usr/local/src/graphene-atstub

include $(GRAPHENE_DIR)/Scripts/Makefile.configs
include $(GRAPHENE_DIR)/Scripts/Makefile.rules

CFLAGS += -I../.. \
          -I../../../../../include/lib \
          -I../mbedtls-adapter/crypto/mbedtls/install/include \
          -I../mbedtls-adapter/crypto/mbedtls/crypto/include \
          -I./protected-files \
          -DCRYPTO_USE_MBEDTLS \
          -D_POSIX_C_SOURCE=200809L \
          -fPIC

LDFLAGS += -L../mbedtls-adapter/crypto/mbedtls/install/lib

all: pf_crypt

# copy the pf_encrypt from Graphene-SGX
pf_crypt:
	cp $(GRAPHENE_DIR)/Pal/src/host/Linux-SGX/tools/pf_crypt/pf_crypt .
	cp $(GRAPHENE_DIR)/Pal/src/host/Linux-SGX/tools/common/libsgx_util.so .
	cp $(GRAPHENE_DIR)/Pal/lib/crypto/mbedtls/crypto/library/libmbedcrypto.so.4 .

help: pf_crypt
	LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./pf_crypt -h

test: all
	LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./pf_crypt gen-key -w ./user.key
	LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./pf_crypt encrypt -w ./user.key -i ./hello.txt -o ./secret.txt
	LD_LIBRARY_PATH=$LD_LIBRARY_PATH:. ./pf_crypt decrypt -w ./user.key -i ./secret.txt -o ./result.txt

clean:
	rm -f pf_crypt libsgx_util.so libmbedcrypto.so.4

clean-all:
	rm -f pf_crypt libsgx_util.so libmbedcrypto.so.4
	rm -f *.key secret.txt result.txt