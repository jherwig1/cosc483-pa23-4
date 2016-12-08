/* This houses the locking function 
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <iostream>
#include <fstream>
#include <openssl/rand.h>
#include <sys/types.h>
#include <dirent.h>
#include <sstream>
#include <vector>

#include "encrypt_or_decrypt.h"
#include "generate_or_verify.h"
#include "hex_string_conv.h"
#include "encrypt_dir.h"
#include "encrypt_dir_lock.h"
#include "rsa_signature.h"
#include "rsa_encrypt.h"

#define SYM_KEY_SIZE 32

using namespace std;

bool verify_rsa_key(Rsa_key &key, string &cert_auth, string dir) {
	ifstream fin;
	string ca_auth;

	//first verify both rsa keys by first verifying the CA that signed them
	fin.open(key.public_sigfile.c_str());
	fin >> ca_auth;
	fin.close();

	//check to make sure it isn't self signed
	if(ca_auth == key.public_keyfile) {
		return false;
	}

	//get rid of the .pub extension
	ca_auth.resize(ca_auth.size()-4);

	//set up the directory
	ca_auth = dir + "/" + ca_auth;

	//also need to return the cert auth
	cert_auth = ca_auth;

	//verify ca -- can assume that it is self signed
	//and has the appropriate extensions
	if(!verify(ca_auth + ".pub", ca_auth + ".hex", ca_auth + ".sig")) {
		return false;
	}

	//Since we can trust the host key, verify the given key
	if(!verify(ca_auth + ".pub", key.public_hexfile, key.public_sigfile)) {
		return false;
	}

	return true;
}

void cp(string inputfile, string outputfile) {
	ifstream fin;
	ofstream fout;

	stringstream ss;

	string temp;

	fin.open(inputfile.c_str());
	ss << fin.rdbuf();
	fin.close();

	fout.open(outputfile.c_str());
	fout << ss.str();
	fout.close();
}


bool lock_dir(string &dir, Rsa_key &locking, Rsa_key &unlocking) {
	UCHAR key[SYM_KEY_SIZE];
	ifstream fin;
	ofstream fout;
	string skey;
	string keyfile = dir + "/symmetric_key_file";
	DIR *d;
	struct dirent *dent;
	string locking_ca, unlocking_ca, herp;
	vector<string> orig;


	//verify locking key
	if(!verify_rsa_key(locking, locking_ca, ".")) {
		cerr << "Locking key verification failed." << endl;
		return false;
	}

	if(!verify_rsa_key(unlocking, unlocking_ca, ".")) {
		cerr << "Unlocking key verification failed." << endl;
		return false;
	}

	//generate a symmetric key
	RAND_bytes(key, SYM_KEY_SIZE);

	//write the key to a file so I can use it for encryption
	binary_to_hex(key, SYM_KEY_SIZE, skey);
	fout.open(keyfile.c_str());
	fout << skey << endl;
	fout.close();

	//cycle through each file in the given directory and encrypt it
	d = opendir(dir.c_str());
	while((dent = readdir(d)) != NULL) {
		string temp = dent->d_name;
		string actual_name = dir + "/" + temp;
		if(temp != "symmetric_key_file" && temp != "." && temp != "..") {
			encrypt_or_decrypt("1", "1", keyfile, actual_name, actual_name);
			orig.push_back(temp);
		}
	}
	closedir(d);

	//cycle through each file in the given directory and encrypt it
	d = opendir(dir.c_str());
	while((dent = readdir(d)) != NULL) {
		string temp = dent->d_name;
		string actual_name = dir + "/" + temp;
		if(temp != "symmetric_key_file" && temp != "." && temp != "..") {
			generate_or_verify(1, "2", keyfile, actual_name, actual_name + ".tag");
		}
	}
	closedir(d);


	//encrypt the symmetric key with the unlocking party's public key
	rsa_encrypt(unlocking.public_keyfile, keyfile, keyfile);

	//sign the the symmetric key using the locking party's private key
	sign(locking.private_keyfile, keyfile, keyfile + ".sig");

	//copy locking party's public key, hex, and sig into directory
	cp(locking.public_keyfile, dir + "/" + locking.public_keyfile);
	cp(locking.public_hexfile, dir + "/" + locking.public_hexfile);
	cp(locking.public_sigfile, dir + "/" + locking.public_sigfile);

	//do the same thing for the ca that verified the locking party
	cp(locking_ca + ".pub", dir + "/" + locking_ca + ".pub");
	cp(locking_ca + ".hex", dir + "/" + locking_ca + ".hex");
	cp(locking_ca + ".sig", dir + "/" + locking_ca + ".sig");

	//add file to tell what the locking public key is
	fout.open((dir + "/locking_key_identifier").c_str());
	fout << locking.public_keyfile << endl;
	fout.close();

	//add file to list the contents of the original directory
	fout.open((dir + "/orig_file_list").c_str());
	for(int i = 0; i < orig.size(); i++) {
		fout << orig[i] << endl;
	}
	fout.close();

	return true;
}
