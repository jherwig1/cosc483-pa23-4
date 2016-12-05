/* This houses the locking function 
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <iostream>
#include <fstream>

#include "encrypt_dir.h"
#include "encrypt_dir_lock.h"
#include "rsa_signature.h"

using namespace std;

bool verify_rsa_key(Rsa_key &key) {
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


bool lock_dir(string &dir, Rsa_key &locking, Rsa_key &unlocking) {
	//verify locking key
	if(!verify_rsa_key(locking)) {
		cerr << "Locking key verification failed." << endl;
		return false;
	}

	if(!verify_rsa_key(unlocking)) {
		cerr << "Unlocking key verification failed." << endl;
		return false;
	}


	return true;
}
