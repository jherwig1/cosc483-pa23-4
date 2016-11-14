/* RSA Decryption
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <math.h>

#include "hex_string_conv.h"

#include "rsa_encrypt.h"

typedef unsigned char UCHAR;

using namespace std;

void rsa_encrypt(string &keyfile, string &inputfile, string &outputfile) {
	//vars
	ifstream fin;
	ofstream fout;
	string public_key, N, encrypted;
	UCHAR *plaintext;
	string plaintext_hex;
	char *temp_string;
	int security_param_bytes, security_param, i, j, padding;
	int stride, num_blocks, block_num, block_size, size;
	string enc;
	string o;
	UCHAR padded;


	/* BN vals is N, and public key */
	BIGNUM *BN_vals[3];
	BIGNUM *BN_N;
	BIGNUM *BN_public_key;
	BIGNUM *BN_encrypted;
	BIGNUM *BN_plaintext;

	BN_CTX *ctx;

	BN_N = BN_new();
	BN_encrypted = BN_new();

	ctx = BN_CTX_new();

	for(i = 0; i < 3; i++) {
		BN_vals[i] = NULL;
	}

	//open the keyfile and get the public key
	fin.open(keyfile.c_str());
	fin >> security_param >> N >> public_key;
	fin.close();

	//get N and the private key
	BN_hex2bn(BN_vals, N.c_str());
	BN_hex2bn(BN_vals + 1, public_key.c_str());

	BN_N = BN_vals[0];
	BN_public_key = BN_vals[1];


	/* Read in the hex encoded string to encrypt */
	stringstream stream;
	fin.open(inputfile.c_str());
	fin >> plaintext_hex;
	fin.close();

	/* Get the binary representation of the hex string */
	size = plaintext_hex.size() / 2;
	plaintext = new UCHAR[plaintext_hex.size() / 2];
	hex_to_binary(plaintext_hex, plaintext, plaintext_hex.size() / 2);

	security_param_bytes = security_param / 8;
	stride = security_param_bytes / 2 - 2;
	num_blocks = ceil(size / (stride * 1.0));
	block_size = security_param_bytes;
	UCHAR *output = new UCHAR[(num_blocks + 1) * block_size];

	RAND_poll();
	UCHAR *random_bytes = new UCHAR[security_param_bytes / 2];
	padding = size % stride;
	UCHAR *block;
	UCHAR *ptr;

	block = (UCHAR *) malloc(block_size); //new UCHAR[block_size];
	for (i = 0, j = 0, block_num = 0; i < size; i+= stride, j += block_size, block_num += 1) {
		if (block_num == (num_blocks - 1)) {
			ptr = (UCHAR *) calloc(stride, 1);
			memcpy(ptr, (plaintext + i), size - i);
		} else
			ptr = plaintext + i;

		/* Padding */
		block[0] = 2; //prepend a 2

		/* Generate the random bits */
		RAND_pseudo_bytes(random_bytes, security_param_bytes / 2);
		memcpy((block + 1), random_bytes, security_param_bytes / 2);

		// add the zero byte
		block[1 + security_param_bytes / 2] = 0;

		// add the message
		memcpy((block + 1 + (security_param_bytes / 2)), ptr, stride);

		/* Get the number rep of the block */
		binary_to_hex(block, block_size, o);
		BN_hex2bn(BN_vals + 2, o.c_str());

		BN_plaintext = BN_vals[2];

		/* Compute c = m^e mod N */
		BN_mod_exp(BN_encrypted, BN_plaintext, BN_public_key, BN_N, ctx);

		/* Get the hex rep of the string and add */
		temp_string = BN_bn2hex(BN_encrypted);
		enc += temp_string;
		OPENSSL_free(temp_string);
	}

	free(ptr);
	for (i = 0; i < block_size; i++)
		block[i] = 0;
	block[0] = 2;

	RAND_pseudo_bytes(random_bytes, security_param_bytes / 2);
	memcpy((block + 1), random_bytes, security_param_bytes / 2);
	block[block_size - 1] = padding;

	binary_to_hex(block, block_size, o);
	BN_hex2bn(BN_vals + 2, o.c_str());
	BN_plaintext = BN_vals[2];

	BN_mod_exp(BN_encrypted, BN_plaintext, BN_public_key, BN_N, ctx);

	temp_string = BN_bn2hex(BN_encrypted);
	enc += temp_string;
	OPENSSL_free(temp_string);

	BN_clear_free(BN_N);
	BN_clear_free(BN_plaintext);
	BN_clear_free(BN_encrypted);
	BN_clear_free(BN_public_key);
	BN_CTX_free(ctx);


	fout.open(outputfile.c_str());
	fout << enc;
	fout.close();
	//see how many bytes of padding you need to remove
	//IF SHIT IS BROKEN THIS IS IT
	/*
	padded = (UCHAR)plaintext[plaintext.size() - 1];
	plaintext.resize(plaintext.size()-padded);
	fout.open(outputfile.c_str());
	fout << plaintext;
	fout.close();
	*/
}
