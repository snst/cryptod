./run_cryptod.sh &

export OPENSSL_TRACE=provider
export LD_LIBRARY_PATH=../openssl
export OPENSSL_MODULES=../build/cryptod_ossl_provider

HASH=SHA512
FILE=input3.txt
KEYFILE=aes256_2.key

sleep 0.1

echo ""
echo "Direct openssl"
../openssl/apps/openssl mac -macopt keyfile:$KEYFILE -digest $HASH -in $FILE HMAC 

echo ""
echo "Cryptod openssl"
../openssl/apps/openssl mac -provider libcryptod_provider -macopt hexkey:aa -digest $HASH -in $FILE HMAC 

killall -9 cryptod