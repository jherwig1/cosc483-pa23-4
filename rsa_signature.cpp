/* RSA Encrypt/Decrypt/Keygen Driver
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <string>
#include <cstdlib>
#include <fstream>
#include <algorithm>

#include <openssl/bn.h>
#include <openssl/sha.h>

#include "rsa_signature.h"
#include "hex_string_conv.h"

using namespace std;

#define SIGN "1"
#define VERIFY "2"

/* Compute the hash of a hex string */
string h_hash(string text) {
	unsigned char *a_input, *h_input;
	string hex_hash;

	a_input = new unsigned char[text.size() / 2];
	hex_to_binary(text, a_input, text.size() / 2);
	h_input = new unsigned char[HASH_SIZE];

	/* Hash the message using sha2 */
	SHA256(a_input, text.size() / 2, h_input);
	binary_to_hex(h_input, HASH_SIZE, hex_hash);


	delete a_input;
	delete h_input;
	return hex_hash;
}

/* Compute the signature on a text using an rsa key */
string compute_signature(string key, string N, int sec_param, string text) {
	string input, hex_hash, outputstring;
	int i;

	BIGNUM *BN_vals[3];
	BIGNUM *BN_N;
	BIGNUM *BN_signature;
	BIGNUM *BN_hashed;
	BIGNUM *BN_key;

	BN_CTX *ctx;

	ifstream fin;
	ofstream fout;

	BN_N = BN_new();
	BN_signature = BN_new();
	ctx = BN_CTX_new();

	for (i = 0; i < 3; i++) BN_vals[i] = NULL;

	/* Get the big number reps of N and the key */
	BN_hex2bn(BN_vals, N.c_str());
	BN_hex2bn(BN_vals + 1, key.c_str());

	BN_N = BN_vals[0];
	BN_key = BN_vals[1];

	/* Get the big number rep of the text */
	BN_hex2bn(BN_vals + 2, text.c_str());
	BN_hashed = BN_vals[2];

	/* Compute sig = m ^ key mod N */
	BN_mod_exp(BN_signature, BN_hashed, BN_key, BN_N, ctx);

	/* return the hex of the signature */
	return BN_bn2hex(BN_signature);

}

void sign(string keyfile, string plaintext, string outputfile) {
	string outputstring, N, key, text, hex_hash;
	int sec_param;
	ofstream fout;
	ifstream fin;

	/* Read in the key and plaintext */
	fin.open(keyfile.c_str());
	fin >> sec_param >> N >> key;
	fin.close();

	fin.open(plaintext.c_str());
	fin >> text;
	fin.close();

	/* Compute the hash */
	hex_hash = h_hash(text);

	/* Compute the signature using the private key*/
	outputstring = compute_signature(key, N, sec_param, hex_hash);

	/* Write the signature */
	fout.open(outputfile.c_str());
	fout << outputstring << endl;
	fout.close();
}


bool verify(string keyfile, string plaintext, string sigfile) {
	string computedsig, signature, key, N, hex_hash, text;
	int sec_param;
	ofstream fout;
	ifstream fin;

	/* Read in the key, text, and signature */
	fin.open(keyfile.c_str());
	fin >> sec_param >> N >> key;
	fin.close();

	fin.open(plaintext.c_str());
	fin >> text;
	fin.close();

	fin.open(sigfile.c_str());
	fin >> signature;
	fout.close();

	/* Compute the hex */
	hex_hash = h_hash(text);

	/* Compute the signature using the public key */
	computedsig = compute_signature(key, N, sec_param, signature);

	transform(computedsig.begin(), computedsig.end(), computedsig.begin(), ::tolower); // make it lowercase

	return computedsig == hex_hash;
}
