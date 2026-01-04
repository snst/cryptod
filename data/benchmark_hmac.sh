#!/bin/bash
# Simple HMAC benchmark using OpenSSL CLI

# sudo apt install bc

#./run_cryptod.sh &

export OPENSSL_TRACE=provider
export LD_LIBRARY_PATH=../openssl
export OPENSSL_MODULES=../build/cryptod_ossl_provider

# Config
ITERATIONS=1

HASH=SHA512
KEYFILE=aes256_2.key
DATA_SIZE=1024
#TMP_FILE=$(mktemp)
TMP_FILE=data${DATA_SIZE}.tmp

if ! [ -f $TMP_FILE ]; then
head -c $DATA_SIZE /dev/urandom > $TMP_FILE
fi

echo "Benchmarking HMAC-$HASH on $DATA_SIZE bytes, $ITERATIONS iterations..."

START=$(date +%s.%N)

for i in $(seq 1 $ITERATIONS); do
    
    ../openssl/apps/openssl mac -macopt keyfile:$KEYFILE -digest $HASH -in $TMP_FILE HMAC > /dev/null
    #../openssl/apps/openssl mac -provider libcryptod_provider -macopt hexkey:aa -digest $HASH -in $TMP_FILE HMAC > /dev/null

done

END=$(date +%s.%N)

# Calculate elapsed time
ELAPSED=$(echo "$END - $START" | bc)
BYTES_TOTAL=$(($DATA_SIZE * $ITERATIONS))
THROUGHPUT=$(echo "$BYTES_TOTAL / $ELAPSED" | bc)

echo "Elapsed time: $ELAPSED seconds"
echo "Processed: $BYTES_TOTAL bytes"
echo "Approx. throughput: $THROUGHPUT bytes/sec"

#rm -f $TMP_FILE

#killall -9 cryptod