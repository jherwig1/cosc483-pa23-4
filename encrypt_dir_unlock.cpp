/* Unlock the directory
 * Last code of the semester
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <fstream>
#include <iostream>
#include <map>

#include "encrypt_dir.h"
#include "encrypt_dir_lock.h"
#include "encrypt_dir_unlock.h"
#include "rsa_signature.h"
#include "rsa_decrypt.h"
#include "encrypt_or_decrypt.h"
#include "generate_or_verify.h"

using namespace std;

bool unlock_dir(string &dir, Rsa_key &unlocking) {
	ifstream fin;
	Rsa_key locking;
	string temp;
	string locking_ca;
	string identity;
	string herp;
	map<string, string> orig_files;
	map<string, string>::iterator it;

	//verify the locking key's identity
	fin.open((dir + "/locking_key_identifier").c_str());
	fin >> temp;
	fin.close();

	temp.resize(temp.size()-4);

	locking.public_keyfile = dir + "/" + temp + ".pub";
	locking.public_hexfile = dir + "/" + temp + ".hex";
	locking.public_sigfile = dir + "/" + temp + ".sig";

	if(!verify_rsa_key(locking, locking_ca, dir)) {
		cerr << "Locking key verification failed." << endl;
		return false;
	}

	//get the identity
	fin.open(locking.public_keyfile.c_str());
	fin >> identity;
	fin.close();

	cout << "Identity of locking party: " << identity << endl;

	//verify the symmetric key
	if(!verify(locking.public_keyfile, dir + "/symmetric_key_file", dir + "/symmetric_key_file.sig")) {
		cerr << "Symmetric Key Verification Failed" << endl;
		return false;
	}

	string sym_key = dir + "/symmetric_key_file";

	//decrypt the symmetric key
	rsa_decrypt(unlocking.private_keyfile, sym_key, sym_key);

	//read in the original list of files
	fin.open((dir + "/orig_file_list").c_str());
	while(fin >> temp) {
		orig_files[dir + "/" + temp] = dir + "/" + temp + ".tag";
	}

	//verify them
	it = orig_files.begin();
	while(it != orig_files.end()) {
		if(!generate_or_verify(1, "1", sym_key, it->first, it->second)) {
			cerr << "File " << it->first << " could not be verified with tagfile " << it->second << endl;
			return false;
		}
		++it;
	}

	//decrypt them
	it = orig_files.begin();
	while(it != orig_files.end()) {
		encrypt_or_decrypt("1", "2", sym_key, it->first, it->first);
		++it;
	}

	//delete the tag files (do this here so you don't fry the directory)
	it = orig_files.begin();
	while(it != orig_files.end()) {
		remove(it->second.c_str());
		++it;
	}

	//remove all the files we no longer need
	remove(locking.public_keyfile.c_str());
	remove(locking.public_hexfile.c_str());
	remove(locking.public_sigfile.c_str());
	remove((locking_ca + ".pub").c_str());
	remove((locking_ca + ".hex").c_str());
	remove((locking_ca + ".sig").c_str());
	remove((dir + "/symmetric_key_file").c_str());
	remove((dir + "/symmetric_key_file.sig").c_str());
	remove((dir + "/locking_key_identifier").c_str());
	remove((dir + "/orig_file_list").c_str());

	return true;
}
