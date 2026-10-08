
openssl mac \
  -provider-path /workspaces/cryptod/client/build/ossl_provider/ \
  -provider libcryptod_provider \
  -digest SHA256 \
  -macopt "key_label:key123" \
  HMAC < data.txt  