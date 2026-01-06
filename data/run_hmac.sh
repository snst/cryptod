export OPENSSL_TRACE=provider
export LD_LIBRARY_PATH=../openssl
export OPENSSL_MODULES=../build/cryptod_ossl_provider

HASH=SHA512
FILE=input3.txt
KEYFILE=aes256_2.key

../openssl/apps/openssl mac -provider libcryptod_provider -macopt key:[0xaa] -digest $HASH -in $FILE HMAC 
