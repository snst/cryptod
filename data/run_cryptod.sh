rm keystore.dat

KEYSTORE_CLI=../build/keystore_cli/keystore_cli
INI=cryptod.ini

$KEYSTORE_CLI -c $INI -l
$KEYSTORE_CLI -c $INI -a -k 0x11 -i aes256_1.key
$KEYSTORE_CLI -c $INI -a -k 0x22 -i aes256_2.key
$KEYSTORE_CLI -c $INI -l

../build/crypto_daemon/cryptod -c cryptod.ini
