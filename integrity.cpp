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
#include <string.h>

#include "cbc.h"
#include "hash_and_mac.h"
#include "hex_string_conv.h"

typedef std::basic_string<unsigned char> u_string;
extern u_string encode(u_string key, u_string data);
extern u_string decode(u_string key, u_string data);

using namespace std;

#define HASH 1
#define CBC 2
#define VERIFY "1"
#define GENERATE "2"
#define BLOCK_SIZE 16

#define DEBUG 0


int generate(int mode, unsigned char *key, unsigned char *text, int N, string tagfile) {
	if (mode == HASH)
		return hash_and_mac_generate(key, text, N, tagfile);
	return cbc_mac_generate(key, text, N, tagfile);
}

int verify(int mode, unsigned char *key, unsigned char *text, int N, string tagfile) {
	if (mode == HASH)
		return hash_and_mac_verify(key, text, N, tagfile);
	return cbc_mac_verify(key, text, N, tagfile);
}

int main(int argc, char *argv[]) {
	string usage = "usage: ./driver mode action keyfile inputfile outputfile\n";
	string action, keyfile, textfile, tagfile;
	int mode;
	u_string output;
	FILE *fout;
	ifstream fin;
	stringstream keyf, textf;

	if (argc == 1) {
		cout << "Select a mode\nEnter 1 for Hash-and-Mac and 2 for CBC-Mac: ";
		cin >> mode;
		cout << "Select an action\nEnter 1 for verify and 2 for tag generation: ";
		cin >> action;
		cout << "Key file: ";
		cin >> keyfile;
		cout << "Input file: ";
		cin >> textfile;
		cout << "Tag file: ";
		cin >> tagfile;
	} else if (argc != 6) {
		cerr << "Not enough arguments provided\n";
		cerr << usage;
		exit(1);
	} else {
		mode = atoi(argv[1]);
		action = argv[2];
		keyfile = argv[3];
		textfile = argv[4];
		tagfile = argv[5];
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
	unsigned int key_size;
	unsigned int text_size;

	SSL_load_error_strings();
	key = new unsigned char[key_ref.size()];
	text = new unsigned char[text_ref.size()];

	//because it is written in hex and we are converting to binary
	key_size = key_ref.size() / 2;
	text_size = text_ref.size() / 2;

	hex_to_binary(key_ref, key, key_size);
	hex_to_binary(text_ref, text, key_size);

	int N;

	/* Run the correct action */
	if (action == GENERATE)
		N = generate(mode, key, text, text_size, tagfile);
	else {
		if (verify(mode, key, text, text_size, tagfile)) {
			cout << "The tag verifies the message\n";
		} else
			cout << "The tag does not verify the message\n";
	}

	return 1;
}
