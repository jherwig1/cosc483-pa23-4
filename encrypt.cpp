#include <iostream>

#include "encrypt_or_decrypt.h"

using namespace std;

int main(int argc, char *argv[]) {
	string usage = "usage: ./encrypt mode action keyfile inputfile outputfile\n";
	string mode, action, keyfile, textfile, outputfile, temp_out;

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
	
	return encrypt_or_decrypt(mode, action, keyfile, textfile, outputfile);
}
