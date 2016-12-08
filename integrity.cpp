#include <iostream>
#include <cstdlib>

#include "generate_or_verify.h"

using namespace std;

int main(int argc, char *argv[]) {
	string usage = "usage: ./driver mode action keyfile inputfile outputfile\n";
	string action, keyfile, textfile, tagfile;
	int mode;

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

	int n = generate_or_verify(mode, action, keyfile, textfile, tagfile);
	if(mode == 1) {
		if(n) {
			cout << "The tag verifies the message." << endl;
		} else
			cout << "The tag does not verify the message." << endl;
	}

	return 0;
}
