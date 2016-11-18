/* RSA Encrypt/Decrypt/Keygen Driver
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <string>

#include "rsa_signature.h"
#include "hex_string_conv.h"

using namespace std;

void print_usage(string name) {
	cerr << "usage: "<< name;
	/*cerr << " action keyfile inputfile outputfile [securityparam]"; */
	cerr << endl;

}
int main(int argc, char *argv[]) {
	//vars
	string action, keyfile, textfile, outputfile;
	string sigfile;
	unsigned int security_param;

	//either run program interactively or read in CL args
	if (argc == 1) {
		cout << "Select an action\nEnter " << SIGN << " for sign, " << VERIFY << " for verification: ";
		cin >> action;
		if(action == SIGN) {
			cout << "Private key file (does not have .pub): ";
			cin >> keyfile;
			cout << "Plaintext file: ";
			cin >> textfile;
			cout << "Output file: ";
			cin >> outputfile;
			sign(keyfile, textfile, outputfile);
		} else if(action == VERIFY) {
			cout << "Public Key File: ";
			cin >> keyfile;
			cout << "Plaintext file: ";
			cin >> textfile;
			cout << "Signature file: ";
			cin >> sigfile;
			if (verify(keyfile, textfile, sigfile))
				cout << "The signature verifies the file\n";
			else
				cout << "The signature does not verify the file\n";
		} else {
			print_usage(argv[0]);
			return 1;
		}
	} else {
		print_usage(argv[0]);
		return 1;
	}

	return 0;
}

