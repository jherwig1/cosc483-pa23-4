/* RSA Encrypt/Decrypt/Keygen Driver
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <iostream>
#include <cstdlib>
#include <fstream>

#include "rsa_keygen.h"
#include "rsa_decrypt.h"
#include "rsa_encrypt.h"


using namespace std;

#define KEYGEN "1"
#define ENCRYPT "2"
#define DECRYPT "3"

void print_usage(string name) {
	cerr << "usage: "<< name;
	/*cerr << " action keyfile inputfile outputfile [securityparam]"; */
	cerr << endl;

}

int main(int argc, char *argv[]) {
	//vars
	ifstream fin;
	string action, keyfile, textfile, outputfile, identity, sigfile;
	unsigned int security_param;

	//either run program interactively or read in CL args
	if (argc == 1) {
		cout << "Select an action\nEnter " << KEYGEN << " for keygen, " << ENCRYPT << " for encryption or " << DECRYPT << " for decryption: ";
		cin >> action;
		if(action == KEYGEN) {
			cout << "Security Param: ";
			cin >> security_param;
			cout << "Keyfile: ";
			cin >> keyfile;
			cout << "Identity: ";
			cin >> identity;
			cout << "Signature private key (Enter None for self-sig): ";
			cin >> sigfile;
			rsa_keygen(security_param, keyfile, identity, sigfile);
		} else if(action == ENCRYPT) {
			cout << "Public Key File: ";
			cin >> keyfile;
			cout << "Plaintext file: ";
			cin >> textfile;
			cout << "Output file: ";
			cin >> outputfile;
			rsa_encrypt(keyfile, textfile, outputfile);	
		} else if(action == DECRYPT) {
			cout << "Private key file (does not have .pub): ";
			cin >> keyfile;
			cout << "Ciphertext file: ";
			cin >> textfile;
			cout << "Output file: ";
			cin >> outputfile;
			rsa_decrypt(keyfile, textfile, outputfile);
		}
/*	else if (argc >= 5 && argc <= 6) {
		action = argv[1];
		keyfile = argv[2];
		textfile = argv[3];
		outputfile = argv[4];
		if (action == KEYGEN) {
			security_param = atoi(argv[5]);
		}*/
	} else {
		print_usage(argv[0]);
		return 1;
	}

	return 0;
}

