/* RSA Encrypt/Decrypt/Keygen Driver
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <iostream>
#include <cstdlib>
#include <fstream>

#include "rsa_keygen.h"

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
	string action, keyfile, textfile, outputfile;
	unsigned int security_param;

	//either run program interactively or read in CL args
	if (argc == 1) {
		cout << "Select an action\nEnter " << KEYGEN << " for keygen, " << ENCRYPT << " for encryption or " << DECRYPT << " for decryption: ";
		cin >> action;
		cout << "Key file: ";
		cin >> keyfile;
		if(action != KEYGEN) {
			cout << "Input file: ";
			cin >> textfile;
			cout << "Output file: ";
			cin >> outputfile;
		}
		else  {
			cout << "Security Param: ";
			cin >> security_param;
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

	if(action == KEYGEN) {
		rsa_keygen(security_param, keyfile);
	}
/*
	//Read in the keyfile and the textfile
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
*/
	return 0;
}

