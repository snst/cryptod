openssl dgst -sha256 -sign ec_private.der -out signature.der -keyform DER input1.txt
openssl dgst -sha256 -verify ec_public.der -keyform DER -signature signature.der input1.txt
openssl dgst -sha256 -verify ec_public.der -keyform DER -signature signature.der input2.txt