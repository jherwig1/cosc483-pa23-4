/* RSA Decryption
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <fstream>
#include <iostream>
#include <string.h>
#include <cctype>
#include <openssl/bn.h>
#include <openssl/crypto.h>

#include "rsa_decrypt.h"

typedef unsigned char UCHAR;

using namespace std;

void rsa_decrypt(string &keyfile, string &inputfile, string &outputfile) {
	//vars
	ifstream fin;
	ofstream fout;
	string private_key, N, encrypted, plaintext, identity;
	char *temp_string;
	int security_param, i;
	//UCHAR padded;

	BIGNUM *BN_vals[3];
	BIGNUM *BN_N;
	BIGNUM *BN_private_key;
	BIGNUM *BN_encrypted;
	BIGNUM *BN_plaintext;

	BN_CTX *ctx;

	BN_N = BN_new();
	BN_plaintext = BN_new();

	ctx = BN_CTX_new();

	for(i = 0; i < 3; i++) {
		BN_vals[i] = NULL;
	}
	
	//open the keyfile and get the private key
	fin.open(keyfile.c_str());
	fin >> identity >> security_param >> N >> private_key;
	fin.close();

	//get N and the private key
	BN_hex2bn(BN_vals, N.c_str());
	BN_hex2bn(BN_vals + 1, private_key.c_str());

	BN_N = BN_vals[0];
	BN_private_key = BN_vals[1];


	//get input
	fin.open(inputfile.c_str());
	fin >> encrypted;
	fin.close();


	int padded = 0;
	int delta = security_param / 2;

	//for each block of input, decrypt it and delete the padding
	//then add it to the output
	for(i = 0; i < encrypted.size(); i += delta) {
		char *block = (char *)malloc((delta) + 1);
		strncpy(block, encrypted.c_str() + i, delta);
		block[(delta)] = 0x00;
		BN_hex2bn(BN_vals + 2, block);
		BN_encrypted = BN_vals[2];

		BN_mod_exp(BN_plaintext, BN_encrypted, BN_private_key, BN_N, ctx);
		//BN_copy(BN_plaintext, BN_encrypted);

		//create masking stuff
		BIGNUM *BN_padding = BN_new();

		BN_copy(BN_padding, BN_plaintext);
		BN_mask_bits(BN_padding, 8);
		padded = BN_get_word(BN_padding);

		//take off all the RSA padding
		temp_string = BN_bn2hex(BN_plaintext);
		//only increment by the randomness and 2 of the 3 added bytes
		//it cuts off the leading zeros
		plaintext += temp_string + 2*(security_param / (8*2)) + 2*2;
		OPENSSL_free(temp_string);
		BN_clear(BN_plaintext);
		BN_clear_free(BN_padding);
	}

	BN_clear_free(BN_N);
	BN_clear_free(BN_plaintext);
	BN_clear_free(BN_encrypted);
	BN_clear_free(BN_private_key);
	BN_CTX_free(ctx);


	//see how many bytes of padding you need to remove
	plaintext.resize(plaintext.size()-padded*2);

	for(i = 0; i < plaintext.size(); i++) {
		plaintext[i] = tolower(plaintext[i]);
	}

	fout.open(outputfile.c_str());
	fout << plaintext;
	fout.close();
}
