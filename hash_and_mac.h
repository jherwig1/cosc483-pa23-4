#ifndef HASH_MAC_HEADER
#define HASH_MAC_HEADER

#include <string>
using namespace std;
int hash_and_mac_generate(unsigned char *key, unsigned char *text, unsigned int N, string tagfile);
int hash_and_mac_verify(unsigned char *key, unsigned char *text, unsigned int N, string tagfile);

#endif
