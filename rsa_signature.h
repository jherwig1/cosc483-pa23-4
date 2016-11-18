#ifndef __RSA_SIG__
#define __RSA_SIG__

/* RSA Encrypt/Decrypt/Keygen Driver
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <iostream>
#include <string>
#include <cstdlib>
#include <fstream>
#include <algorithm>

#include <openssl/bn.h>
#include <openssl/sha.h>

#include "hex_string_conv.h"

using namespace std;

#define SIGN "1"
#define VERIFY "2"

const int HASH_SIZE = 32;

/* Compute the hash of a hex string */
string h_hash(string text);

/* Compute the signature on a text using an rsa key */
string compute_signature(string key, string N, int sec_param, string text);

/* Sign a plaintext */
void sign(string keyfile, string plaintext, string outputfile);

/* Verify a signature on the plaintext */
bool verify(string keyfile, string plaintext, string sigfile);
#endif
