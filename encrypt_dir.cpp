/* Programming Assignment 3 
 * Problem 3
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <iostream>

#include "encrypt_dir.h"
#include "encrypt_dir_lock.h"
#include "encrypt_dir_unlock.h"
#include "rsa_signature.h"

using namespace std;


string prompt(string pr) {
	string temp;

	cout << pr;
	cin >> temp;
	return temp;
}


//so this one does not have commandline arguments
int main() {
	string dir;
	string mode;
	Rsa_key locking;
	Rsa_key unlocking;
	

	mode = prompt("Mode (lock or unlock): ");

	//get necessary keyfiles and lock/unlock the files
	if(mode == LOCK) {
		dir = prompt("Directory: ");

		locking.private_keyfile = prompt("Locking private keyfile: ");
		locking.public_keyfile = prompt("Locking public keyfile (has .pub extension): ");
		locking.public_hexfile = prompt("Locking publix hexfile (has .hex extension): ");
		locking.public_sigfile = prompt("Locking public key signature (has .sig extension): ");

		unlocking.public_keyfile = prompt("Unlocking public keyfile (has .pub extension): ");
		unlocking.public_hexfile = prompt("Unlocking public hexfile (has .hex extension): ");
		unlocking.public_sigfile = prompt("Unlocking pub key signature (has .sig extension): ");
		
		lock_dir(dir, locking, unlocking);
	} else if(mode == UNLOCK) {
		dir = prompt("Directory: ");

		unlocking.private_keyfile = prompt("Unlocking private keyfile: ");
		unlocking.public_keyfile = prompt("Unlocking pub keyfile (has .pub extension): ");
		unlocking.public_hexfile = prompt("Unlocking public hexfile (has .hex extension): ");
		unlocking.public_sigfile = prompt("Unlocking pub key signature (has .sig extension): ");
		unlock_dir(dir, unlocking);
	} else {
		cout << "Invalid Mode. Please Try again." << endl;
	}

	return 0;
}


