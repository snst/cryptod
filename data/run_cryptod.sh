rm keystore.dat

KEYSTORE_CLI=../build/keystore_cli/keystore_cli
INI=cryptod.ini
KEYFILE=aes256_2.key

$KEYSTORE_CLI -c $INI -l
$KEYSTORE_CLI -c $INI -a -k 0xaa -i $KEYFILE
$KEYSTORE_CLI -c $INI -l

../build/crypto_daemon/cryptod -c cryptod.ini
