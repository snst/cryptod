
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

OPENSSL=openssl

if ! [ -d $OPENSSL ]; then
    git clone https://github.com/openssl/openssl.git
fi 

if [ -d $OPENSSL ]; then
    pushd .
    cd $OPENSSL
    git checkout openssl-3.5.6
    #./Configure debug --prefix=/usr/local/ssl --openssldir=/usr/local/ssl '-Wl,--enable-new-dtags,-rpath,$(LIBRPATH)'

    ./config -d no-asm -g3 -O0 --prefix=/usr/local/ssl --openssldir=/usr/local/ssl '-Wl,--enable-new-dtags,-rpath,$(LIBRPATH)'

    sudo make install
    popd
fi