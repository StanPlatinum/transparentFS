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

protected_files.o: ../../protected-files/protected_files.c
	$(call cmd,cc_o_c)

lru_cache.o: ../../protected-files/lru_cache.c
	$(call cmd,cc_o_c)

all: libsgx_util.so

protected_files.o

libsgx_util.so: lru_cache.o pf_util.o protected_files.o
	# $(CC) $^ $(LDFLAGS) ../../lib/crypto/adapters/mbedtls_encoding.o -lmbedcrypto -shared -o $@
	$(CC) $^ $(LDFLAGS) -lmbedcrypto -shared -o $@
