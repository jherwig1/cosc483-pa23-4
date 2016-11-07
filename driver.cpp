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

#include "cbc.h"
#include "ctr.h"

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
	if (mode == CTR)
		return ctr_encrypt(key, text, N, output);
	return cbc_encrypt(key, (unsigned char *) text, N, output);
} 

int decrypt(string mode, unsigned char *key, unsigned char*text, unsigned int N, u_string &output) {
	if (mode == CTR)
		return ctr_decrypt(key, text, N, output);
	return cbc_decrypt(key, text, N, output);
} 

int main(int argc, char *argv[]) {
	string usage = "usage: ./driver mode action keyfile inputfile outputfile\n";
	string mode, action, keyfile, textfile, outputfile;
	u_string output;
	FILE *fout;
	ifstream fin;
	stringstream keyf, textf;

	if (argc == 1) {
		cout << "Select a mode\nEnter 1 for CTC and 2 for CBC: ";
		cin >> mode;
		cout << "Select an action\nEnter 1 for encryption and 2 for decryption: ";
		cin >> action;
		cout << "Key file: ";
		cin >> keyfile;
		cout << "Input file: ";
		cin >> textfile;
		cout << "Output file: ";
		cin >> outputfile;
	} else if (argc != 6) {
		cerr << "Not enough arguments provided\n";
		cerr << usage;
		return 0;
	} else {
		mode = argv[1];
		action = argv[2];
		keyfile = argv[3];
		textfile = argv[4];
		outputfile = argv[5];
	}

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
	key = new unsigned char[key_ref.size() + 1];
	text = new unsigned char[text_ref.size() + 1];
	memcpy(key, key_ref.c_str(), key_ref.size());
	memcpy(text, text_ref.c_str(), text_ref.size());

	int N;

	/* Run the correct action */
	if (action == ENCRYPTION)
		N = encrypt(mode, key, text, text_ref.size(), output);
	else
		N = decrypt(mode, key, text, text_ref.size(), output);

	fout = fopen(outputfile.c_str(), "wb");
	if (fout == NULL) {
		cerr << "Can't open the output file for writing\n";
		exit(1);
	}

	fwrite(output.c_str(), sizeof(unsigned char), N, fout);
	fclose(fout);

	return 1;
}
