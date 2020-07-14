# Use one of these commands to build the manifest for dcap:
#
# - make
# - make DEBUG=1
# - make SGX=1
# - make SGX=1 DEBUG=1
#
# Use `make clean` to remove Graphene-generated files.

THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
DCAP_DIR ?= /usr/bin/

# Relative path to Graphene root and key for enclave signing
GRAPHENEDIR ?= ../..
SGX_SIGNER_KEY ?= $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem

ifeq ($(DEBUG),1)
GRAPHENEDEBUG = inline
else
GRAPHENEDEBUG = none
endif

.PHONY: all
all: dcap.manifest pal_loader
ifeq ($(SGX),1)
all: dcap.token
endif

include ../../Scripts/Makefile.configs

# DCAP dependencies (generated from ldd). For SGX, the manifest needs to list all the libraries
# loaded during execution, so that the signer can include the file hashes.

# We need to replace Glibc dependencies with Graphene-specific Glibc. The Glibc binaries are
# already listed in the manifest template, so we can skip them from the ldd results.
GLIBC_DEPS = linux-vdso.so.1 /lib64/ld-linux-x86-64.so.2 libc.so.6 libm.so.6 librt.so.1 \
			 libdl.so.2 libpthread.so.0 libutil.so.1 libresolv.so.2 libnss_dns.so.2

# List all the dcap dependencies, besides Glibc libraries
.INTERMEDIATE: list-deps
list-deps: dcap
	@ldd ./dcap > $@
	@ldd /usr/$(ARCH_LIBDIR)/libsgx_dcap_quoteverify.so >> $@
	@ldd /usr/$(ARCH_LIBDIR)/libdcap_quoteprov.so >> $@
#	@ldd /usr/$(ARCH_LIBDIR)/libsgx_urts.so >> $@

.INTERMEDIATE: dcap-deps
dcap-deps: list-deps
	@cat list-deps | \
		awk '{if ($$2 =="=>") {print $$3}}' | \
		sort | uniq | grep -v $(patsubst %,-e %,$(GLIBC_DEPS)) > $@

# Generate manifest rules for dcap dependencies
.INTERMEDIATE: dcap-trusted-libs
dcap-trusted-libs: dcap-deps
	@for F in `cat dcap-deps`; do \
		N=`basename $$F | tr --delete '.' | tr --delete '-' | tr --delete '+'`; \
		echo -n "sgx.trusted_files.$$N = file:$$F\\\\n"; \
	done > $@
	cat $@

dcap.manifest: dcap.manifest.template dcap-trusted-libs
	@sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' \
		-e 's|$$(GRAPHENEDEBUG)|'"$(GRAPHENEDEBUG)"'|g' \
		-e 's|$$(DCAP_TRUSTED_LIBS)|'"`cat dcap-trusted-libs`"'|g' \
		-e 's|$$(ARCH_LIBDIR)|'"$(ARCH_LIBDIR)"'|g' \
		$< > $@

# Generate SGX-specific manifest, enclave signature, and token for enclave initialization
dcap.manifest.sgx: dcap.manifest
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
		-libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so \
		-key $(SGX_SIGNER_KEY) \
		-manifest $< -output $@

dcap.sig: dcap.manifest.sgx

dcap.token: dcap.sig
	$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
		-output $@ -sig $^

dcap: src/dcap.c
	$(CC) -Wl,-E -Wall -o dcap src/dcap.c -ldl

# Extra executables
pal_loader:
	ln -s $(GRAPHENEDIR)/Runtime/pal_loader $@

.PHONY: check
check: all
	./pal_loader dcap.manifest

.PHONY: clean
clean:
	$(RM) *.manifest *.manifest.sgx *.token *.sig pal_loader OUTPUT dcap

.PHONY: distclean
distclean: clean
