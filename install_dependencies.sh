
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Stefan Schmidt

CAPNPROTO=capnproto-c++-1.3.0
OPENSSL=openssl

if ! [ -f $CAPNPROTO.tar.gz ]; then
    curl -O https://capnproto.org/$CAPNPROTO.tar.gz
    tar zxf $CAPNPROTO.tar.gz
fi

if [ -d $CAPNPROTO ]; then
    pushd .
    cd $CAPNPROTO
    ./configure
    make -j6 check
    sudo make install
    #mkdir -p build && cd build
    #cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=ON ..
    #make -j
    #sudo make install
    popd
fi

if ! [ -d $OPENSSL ]; then
    git clone https://github.com/openssl/openssl.git
fi 

if [ -d $OPENSSL ]; then
    pushd .
    cd $OPENSSL
    #./Configure debug --prefix=/usr/local/ssl --openssldir=/usr/local/ssl '-Wl,--enable-new-dtags,-rpath,$(LIBRPATH)'

    ./config -d no-asm -g3 -O0 --prefix=/usr/local/ssl --openssldir=/usr/local/ssl '-Wl,--enable-new-dtags,-rpath,$(LIBRPATH)'

    sudo make install
    popd
fi
