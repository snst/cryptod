#!/bin/bash

./run_cryptod.sh &

sleep 0.5

export OPENSSL_TRACE=provider
export LD_LIBRARY_PATH=../openssl
export OPENSSL_MODULES=../build/cryptod_ossl_provider

../build/test/benchmark/hmac_benchmark 

killall -9 cryptod
