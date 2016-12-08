//had to move this to a different file
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h> 
#include <openssl/ssl.h>
#include <openssl/rand.h>

#include "encrypt_or_decrypt.h"
#include "cbc.h"
#include "ctr.h"
#include "hex_string_conv.h"

typedef std::basic_string<unsigned char> u_string;
extern u_string encode(u_string key, u_string data);
extern u_string decode(u_string key, u_string data);

using namespace std;

#define CTR "1"
#define CBC "2"
#define ENCRYPTION "1"
#define DECRYPTION "2"
#define BLOCK_SIZE 16

#define DEBUG 0

int encrypt(string mode, unsigned char *key, unsigned char *text, unsigned int N, u_string &output) {

	unsigned char *IV = NULL;
	if (mode == CTR)
		return ctr_encrypt(key, text, N, output);
	return cbc_encrypt(key, (unsigned char *) text, N, output, IV);
} 

int decrypt(string mode, unsigned char *key, unsigned char*text, unsigned int N, u_string &output) {
	if (mode == CTR)
		return ctr_decrypt(key, text, N, output);
	return cbc_decrypt(key, text, N, output);
} 

int encrypt_or_decrypt(string mode, string action, string keyfile, string textfile, string outputfile) {
	u_string output;
	ifstream fin;
	ofstream fout;
	stringstream keyf, textf;
	string temp_out;

	/* Read in the keyfile and textfile */
	fin.open(keyfile.c_str());

	if (!fin.is_open()) {
		cerr << "Could not open " << keyfile << " for reading\n";
		exit(1);
	}

	keyf << fin.rdbuf();
	fin.close();

	fin.open(textfile.c_str());
	if (!fin.is_open()) {
		cerr << "Could not open " << textfile << " for reading\n";
		exit(1);
	}
	textf << fin.rdbuf();
	fin.close();

	unsigned char *key, *text;
	const string& key_ref = keyf.str();
	const string& text_ref = textf.str();

	SSL_load_error_strings();
	key = new unsigned char[key_ref.size()];
	text = new unsigned char[text_ref.size()];

	hex_to_binary(key_ref, key, key_ref.size() / 2);
	hex_to_binary(text_ref, text, text_ref.size() / 2);

	int N;

	/* Run the correct action */
	if (action == ENCRYPTION)
		N = encrypt(mode, key, text, text_ref.size() / 2, output);
	else
		N = decrypt(mode, key, text, text_ref.size() / 2, output);

	fout.open(outputfile.c_str());
	if (!fout.is_open()) {
		cerr << "Can't open the output file for writing\n";
		exit(1);
	}


	binary_to_hex((unsigned char *)output.c_str(), N, temp_out);
	fout << temp_out << endl;
	fout.close();

	return 1;
}
