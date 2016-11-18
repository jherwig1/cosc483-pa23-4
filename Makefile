all: encrypt integrity rsa sign

sign: sign.cpp rsa_signature.o hex_string_conv.o
	g++ -o sign rsa_signature.o hex_string_conv.o sign.cpp -lcrypto -lssl
encrypt: encrypt.cpp ecb.o cbc.o ctr.o hex_string_conv.o
	g++ -g -o encrypt ecb.o cbc.o ctr.o hex_string_conv.o encrypt.cpp -lcrypto -lssl
integrity: integrity.cpp ecb.o cbc.o hex_string_conv.o hash_and_mac.o
	g++ -o integrity ecb.o cbc.o hex_string_conv.o hash_and_mac.o integrity.cpp -lcrypto -lssl
rsa: rsa.cpp rsa_keygen.o rsa_decrypt.o rsa_encrypt.o hex_string_conv.o
	g++ -g -o rsa rsa_keygen.o rsa_signature.o rsa_decrypt.o rsa_encrypt.o hex_string_conv.o rsa.cpp -lcrypto -lssl
rsa_keygen.o: rsa_keygen.cpp rsa_keygen.h rsa_signature.o rsa_signature.h hex_string_conv.o
	g++ -g -c -o rsa_keygen.o rsa_signature.o rsa_keygen.cpp
rsa_encrypt.o: rsa_encrypt.cpp rsa_encrypt.h
	g++ -g -c -o rsa_encrypt.o rsa_encrypt.cpp -lm
rsa_decrypt.o: rsa_decrypt.cpp rsa_decrypt.h
	g++ -g -c -o rsa_decrypt.o rsa_decrypt.cpp
rsa_signature.o: rsa_signature.cpp rsa_signature.h hex_string_conv.o 
	g++ -g -c -o rsa_signature.o hex_string_conv.o rsa_signature.cpp  -lcrypto -lssl
ecb.o: ecb.cpp
	g++ -g -c -o ecb.o ecb.cpp -lcrypto -lssl
cbc.o: cbc.cpp cbc.h
	g++ -g -c -o cbc.o cbc.cpp
ctr.o: ctr.cpp ctr.h cbc.h
	g++ -g -c -o ctr.o ctr.cpp
hash_and_mac.o: hash_and_mac.cpp
	g++ -g -c -o hash_and_mac.o hash_and_mac.cpp
hex_string_conv.o: hex_string_conv.cpp hex_string_conv.h
	g++ -g -std=c++11 -c -o hex_string_conv.o hex_string_conv.cpp
clean:
	rm *.o encrypt integrity rsa
