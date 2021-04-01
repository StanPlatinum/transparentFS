# Use one of these commands to build the manifest for your app:
#
# - make
# - make DEBUG=1
# - make SGX=1
# - make SGX=1 DEBUG=1
#
# Use `make clean` to remove Graphene-generated files.

THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
APP_DIR ?= /u/weijliu/transparentFS
APP_NAME := hello


# Relative path to Graphene root and key for enclave signing
GRAPHENEDIR ?= /usr/local/src/graphene-atstub
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENE_LOG_LEVEL = debug
else
GRAPHENE_LOG_LEVEL = error
endif

.PHONY: all
all: $(APP_NAME).manifest $(APP_NAME) pal_loader
ifeq ($(SGX),1)
all: $(APP_NAME).token
endif

include $(GRAPHENEDIR)/Scripts/Makefile.configs

# $(APP_NAME) dependencies (generated from ldd). For SGX, the manifest needs to list all the libraries
# loaded during execution, so that the signer can include the file hashes.

# We need to replace Glibc dependencies with Graphene-specific Glibc. The Glibc binaries are
# already listed in the manifest template, so we can skip them from the ldd results.
# GLIBC_DEPS = linux-vdso.so.1 /lib64/ld-linux-x86-64.so.2 libc.so.6 libpthread.so.0
GLIBC_DEPS = linux-vdso.so.1 

# List all the $(APP_NAME) dependencies, besides Glibc libraries
.INTERMEDIATE: $(APP_NAME)-deps
$(APP_NAME)-deps: $(APP_NAME)
	@echo $(patsubst %,-e %,$(GLIBC_DEPS))
	@ldd $(APP_DIR)/$(APP_NAME) | \
		awk '{if ($$2 =="=>") {print $$1}}' | \
		sort | uniq | grep -v -x $(patsubst %,-e %,$(GLIBC_DEPS)) > $@

# Generate manifest rules for $(APP_NAME) dependencies
.INTERMEDIATE: $(APP_NAME)-trusted-libs
$(APP_NAME)-trusted-libs: $(APP_NAME)-deps
	@for F in `cat $(APP_NAME)-deps`; do \
		P=`ldd $(APP_DIR)/$(APP_NAME) | grep $$F | awk '{print $$3; exit}'`; \
		N=`echo $$F | tr --delete '.' | tr --delete '-'`; \
		echo -n "sgx.trusted_files.$$N = \\\"file:$$P\\\"\\\\n"; \
	done > $@

$(APP_NAME).manifest: $(APP_NAME).manifest.template $(APP_NAME)-trusted-libs
	@sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(APP_DIR)|'"$(APP_DIR)"'|g' \
		-e 's|$$(APP_TRUSTED_LIBS)|'"`cat $(APP_NAME)-trusted-libs`"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

# Generate SGX-specific manifest, enclave signature, and token for enclave initialization
$(APP_NAME).manifest.sgx: $(APP_NAME) $(APP_NAME).manifest
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $(APP_NAME).manifest -output $@

$(APP_NAME).sig: $(APP_NAME).manifest.sgx

$(APP_NAME).token: $(APP_NAME).sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output $@ -sig $^


$(APP_NAME): $(APP_NAME).c
	gcc $< -o $@

pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

.PHONY: run
run: all
	SGX=1 ./pal_loader ./$(APP_NAME)

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig $(APP_NAME) pal_loader OUTPUT *-trusted-libs *-deps
	rm -f data/secret.txt

.PHONY: distclean
distclean: clean
