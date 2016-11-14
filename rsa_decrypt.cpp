/* RSA Decryption
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <fstream>
#include <openssl/bn.h>
#include <openssl/crypto.h>

#include "rsa_decrypt.h"

typedef unsigned char UCHAR;

using namespace std;

void rsa_decrypt(string &keyfile, string &inputfile, string &outputfile) {
	//vars
	ifstream fin;
	ofstream fout;
	string private_key, N, encrypted, plaintext;
	char *temp_string;
	int security_param, i;
	UCHAR padded;

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
	fin >> security_param >> N >> private_key;
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

	//for each block of input, decrypt it and delete the padding
	//then add it to the output
	for(i = 0; i < encrypted.size(); i += security_param) {
		BN_hex2bn(BN_vals + 2, encrypted.c_str() + i);
		BN_encrypted = BN_vals[2];

		BN_mod_exp(BN_plaintext, BN_encrypted, BN_private_key, BN_N, ctx);

		//take off all the RSA padding
		temp_string = BN_bn2hex(BN_plaintext);
		plaintext += temp_string + (security_param / (8*2)) + 3;
		OPENSSL_free(temp_string);
	}

	BN_clear_free(BN_N);
	BN_clear_free(BN_plaintext);
	BN_clear_free(BN_encrypted);
	BN_clear_free(BN_private_key);
	BN_CTX_free(ctx);


	//see how many bytes of padding you need to remove
	//IF SHIT IS BROKEN THIS IS IT
	padded = (UCHAR)plaintext[plaintext.size() - 1];
	plaintext.resize(plaintext.size()-padded);

	fout.open(outputfile.c_str());
	fout << plaintext;
	fout.close();
}
