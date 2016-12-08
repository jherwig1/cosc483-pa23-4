/* Tyler Stuessi
 * Jeremy Herwig
 *
 * Hash and Mac implementation
 */

#include <iostream>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <openssl/md5.h>
#include "hex_string_conv.h"
#include "hash_and_mac.h"
#include "cbc.h"

typedef unsigned char UCHAR;
typedef unsigned int UINT;

using namespace std;

string hash_and_mac(UCHAR *key, UCHAR *text, UINT N) {
	UCHAR md5_digest[MD5_DIGEST_LENGTH];
	u_string ret;
	string output;

	//generate the hash of the text
	MD5(text, N, md5_digest);

	//run the hash through the block cipher
	ret = encode(key, md5_digest);

	//convert the mac to written hex
	binary_to_hex((UCHAR *)ret.c_str(), ret.size(), output);

	output += '\n';

	return output;
}

int hash_and_mac_generate(UCHAR *key, UCHAR *text, UINT N, string tagfile) {
	string output;
	ofstream fout;

	//mac it
	output = hash_and_mac(key, text, N);

	//write to the tagfile
	fout.open(tagfile.c_str());
    if (!fout.is_open()) {
        cerr << "Can't open the output file for writing\n";
        exit(1);
    }

	fout << output;
	fout.close();

	return 1;
}

int hash_and_mac_verify(UCHAR *key, UCHAR *text, UINT N, string tagfile) {
	string tag, output;
	ifstream fin;
	stringstream tagf;

	//get the provided tag
	fin.open(tagfile.c_str());
	tagf << fin.rdbuf();
	tag = tagf.str();

	//mac the text
	output = hash_and_mac(key, text, N);


	//compare the two
	if(output == tag) {
		return 1;
	} else {
		return 0;
	}
}
