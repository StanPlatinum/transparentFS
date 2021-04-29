GRAPHENE_DIR = /usr/local/src/graphene-atstub

include $(GRAPHENE_DIR)/Scripts/Makefile.configs
include $(GRAPHENE_DIR)/Scripts/Makefile.rules
include $(GRAPHENE_DIR)/Pal/src/host/$(PAL_HOST)/Makefile.am

CFLAGS += -fno-stack-protector

CFLAGS += -DCRYPTO_USE_MBEDTLS

CFLAGS += \
	-Icrypto/mbedtls/include \
	-Icrypto/mbedtls/crypto/include

CRYPTO_PROVIDER ?= mbedtls

# Select which crypto adpater you want to use here. This has to match
# the #define in pal_crypto.h.
#
# Unfortunately, we cannot use just one .c file for the adapter. The LibOS
# shim links against the crypto library, but it doesn't use Diffie-Hellman.
# If the Diffie-Hellman stubs are in the same .o file as the SHA1 stubs,
# this pulls Diffie-Hellman code into LibOS shim, resulting in unsatisfied
# symbols.
ifeq ($(CRYPTO_PROVIDER),mbedtls)
crypto_mbedtls_library_objs = \
	crypto/mbedtls/crypto/library/aes.o \
	crypto/mbedtls/crypto/library/base64.o \
	crypto/mbedtls/crypto/library/bignum.o \
	crypto/mbedtls/crypto/library/cipher.o \
	crypto/mbedtls/crypto/library/cipher_wrap.o \
	crypto/mbedtls/crypto/library/cmac.o \
	crypto/mbedtls/crypto/library/ctr_drbg.o \
	crypto/mbedtls/crypto/library/dhm.o \
	crypto/mbedtls/crypto/library/entropy.o \
	crypto/mbedtls/crypto/library/gcm.o \
	crypto/mbedtls/crypto/library/md.o \
	crypto/mbedtls/crypto/library/oid.o \
	crypto/mbedtls/crypto/library/platform_util.o \
	crypto/mbedtls/crypto/library/rsa.o \
	crypto/mbedtls/crypto/library/rsa_internal.o \
	crypto/mbedtls/crypto/library/sha256.o \
	crypto/mbedtls/library/ssl_ciphersuites.o \
	crypto/mbedtls/library/ssl_cli.o \
	crypto/mbedtls/library/ssl_msg.o \
	crypto/mbedtls/library/ssl_srv.o \
	crypto/mbedtls/library/ssl_tls.o
ifeq ($(ARCH),x86_64)
crypto_mbedtls_library_objs += \
	crypto/mbedtls/crypto/library/aesni.o
endif
objs += $(crypto_mbedtls_library_objs)
endif

# objs += mbedtls_adapter.o
# objs += mbedtls_dh.o
# objs += mbedtls_encoding.o

MBEDTLS_VERSION ?= 2.21.0
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= \
	https://github.com/ARMmbed/mbedtls/archive \
	https://packages.grapheneproject.io/distfiles
MBEDTLS_CHECKSUM ?= 320e930b7596ade650ae4fc9ba94b510d05e3a7d63520e121d8fdc7a21602db9

# mbedTLS uses a submodule mbedcrypto, need to download it and move under mbedtls/crypto
MBEDCRYPTO_VERSION ?= 3.1.0
MBEDCRYPTO_SRC ?= mbedcrypto-$(MBEDCRYPTO_VERSION).tar.gz
MBEDCRYPTO_URI ?= \
	https://github.com/ARMmbed/mbed-crypto/archive \
	https://packages.grapheneproject.io/distfiles
MBEDCRYPTO_CHECKSUM ?= 7e171df03560031bc712489930831e70ae4b70ff521a609c6361f36bd5f8b76b

crypto/$(MBEDTLS_SRC):
	# $(GRAPHENE_DIR)/Scripts/download --output $@ $(foreach mirror,$(MBEDTLS_URI),--url $(mirror)/$(MBEDTLS_SRC)) --sha256 $(MBEDTLS_CHECKSUM)
	#need to comment those to fit in bio-sgx's stupid wget
	mv mbedtls-2.21.0.tar.gz crypto/

crypto/$(MBEDCRYPTO_SRC):
	# $(GRAPHENE_DIR)/Scripts/download --output $@ $(foreach mirror,$(MBEDCRYPTO_URI),--url $(mirror)/$(MBEDCRYPTO_SRC)) --sha256 $(MBEDCRYPTO_CHECKSUM)
	mv mbedcrypto-3.1.0.tar.gz crypto/

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
else
MBED_BUILD_TYPE=Release
endif

# First, build mbedtls library against system's glibc and install in ../install. This library is
# used by, for example, LibOS test cases. Second, prepare mbedtls directory to be used during PAL
# build. A custom config.h header replaces libc dependencies with PAL-specific alternatives.
crypto/mbedtls/CMakeLists.txt: crypto/$(MBEDTLS_SRC) crypto/$(MBEDCRYPTO_SRC) crypto/mbedtls-$(MBEDTLS_VERSION).diff
	$(RM) -r crypto/mbedtls
	cd crypto && tar -mxzf $(MBEDTLS_SRC)
	cd crypto && tar -mxzf $(MBEDCRYPTO_SRC)
	mv crypto/mbedtls-mbedtls-$(MBEDTLS_VERSION) crypto/mbedtls
	$(RM) -r crypto/mbedtls/crypto
	mv crypto/mbed-crypto-mbedcrypto-$(MBEDCRYPTO_VERSION) crypto/mbedtls
	mv crypto/mbedtls/mbed-crypto-mbedcrypto-3.1.0 crypto/mbedtls/crypto
	cd crypto/mbedtls && patch -p1 < ../mbedtls-$(MBEDTLS_VERSION).diff || exit 255
	mkdir crypto/mbedtls/install
	cd crypto/mbedtls && perl ./scripts/config.pl set MBEDTLS_CMAC_C && $(MAKE) CFLAGS="" SHARED=1 DESTDIR=install install .
	$(RM) crypto/mbedtls/include/mbedtls/config.h
	$(RM) crypto/mbedtls/crypto/include/mbedtls/config.h

crypto/mbedtls/include/mbedtls/config.h: crypto/config.h crypto/mbedtls/CMakeLists.txt
	cp crypto/config.h crypto/mbedtls/crypto/include/mbedtls
	cp crypto/config.h crypto/mbedtls/include/mbedtls

crypto/mbedtls/crypto/library/aes.c: crypto/mbedtls/CMakeLists.txt crypto/mbedtls/include/mbedtls/config.h
$(filter-out crypto/mbedtls/crypto/library/aes.c,$(patsubst %.o,%.c,$(crypto_mbedtls_library_objs))): crypto/mbedtls/crypto/library/aes.c

crypto:
	mkdir crypto
	cp $(GRAPHENE_DIR)/Pal/lib/crypto/mbedtls-2.21.0.diff ./crypto
	cp $(GRAPHENE_DIR)/Pal/lib/crypto/config.h ./crypto

all: crypto $(objs)

clean:
	$(RM) $(objs)
	#need to fit in the bio-sgx
	mv crypto/mbedtls-2.21.0.tar.gz .
	mv crypto/mbedcrypto-3.1.0.tar.gz .
	rm -rf crypto
