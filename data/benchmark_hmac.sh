#!/bin/bash
# Simple HMAC benchmark using OpenSSL CLI

# sudo apt install bc

#./run_cryptod.sh &

export OPENSSL_TRACE=provider
export LD_LIBRARY_PATH=../openssl
export OPENSSL_MODULES=../build/cryptod_ossl_provider

../build/test/benchmark/hmac_benchmark 


#rm -f $TMP_FILE

#killall -9 cryptod