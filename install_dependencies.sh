
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

CAPNPROTO=capnproto-c++-1.3.0
OPENSSL=openssl

if [ -d $CAPNPROTO ]; then
    echo "Folder $CAPNPROTO already exists.."
else

    curl -O https://capnproto.org/$CAPNPROTO.tar.gz
    tar zxf $CAPNPROTO.tar.gz
    cd $CAPNPROTO
    ./configure
    make -j6 check
    sudo make install
    cd ..
fi

if [ -d $OPENSSL ]; then
    echo "Folder $OPENSSL already exists.."
else
    git clone https://github.com/openssl/openssl.git

    cd $OPENSSL
    ./Configure --prefix=/usr/local/ssl --openssldir=/usr/local/ssl \
    '-Wl,--enable-new-dtags,-rpath,$(LIBRPATH)'
    make install
    cd ..
fi
