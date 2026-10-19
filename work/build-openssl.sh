#!/bin/sh
# Build OpenSSL 1.1.1w for LuaSec with one TLS-1.2 check disabled.
#
# The MDG grid and the Danfoss CC use ECDSA certificates on brainpoolP320r1,
# which is not a registered TLS group (RFC 7027 covers 256/384/512 only).
# OpenSSL >= 1.1.0 rejects such a peer signature algorithm in
# tls12_check_peer_sigalg ("wrong curve"); OpenSSL 3 also rejects the explicit
# EC parameters these certs carry (verify error 94). OpenSSL 1.0.2, which the
# vendor shipped, performed neither check.
set -eux

PREFIX=/opt/ossl111
SRC=openssl-OpenSSL_1_1_1w

cd /tmp
curl -sSL --max-time 600 -o openssl.tgz \
  https://codeload.github.com/openssl/openssl/tar.gz/refs/tags/OpenSSL_1_1_1w
tar xzf openssl.tgz
cd "$SRC"

NEEDLE='if (!tls1_check_group_id(s, tls1_get_group_id(pkey), 1)) {'
grep -q "$NEEDLE" ssl/t1_lib.c
sed -i "s|$NEEDLE|if (0) { /* dlre: accept unregistered curves in TLS 1.2 certs, as 1.0.2 did */|" ssl/t1_lib.c
grep -n 'dlre: accept unregistered' ssl/t1_lib.c

./config --prefix="$PREFIX" --openssldir="$PREFIX/ssl" shared no-tests no-comp
make -j"$(nproc)" > /tmp/openssl-build.log 2>&1 || { tail -30 /tmp/openssl-build.log; exit 1; }
grep -c 't1_lib' /tmp/openssl-build.log
make install_sw > /tmp/openssl-install.log 2>&1 || { tail -30 /tmp/openssl-install.log; exit 1; }
LD_LIBRARY_PATH="$PREFIX/lib" "$PREFIX/bin/openssl" version
ls -l "$PREFIX/lib/libssl.so.1.1" "$PREFIX/lib/libcrypto.so.1.1"

cd /tmp && rm -rf openssl.tgz "$SRC"
