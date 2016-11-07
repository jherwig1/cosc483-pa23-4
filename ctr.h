#ifndef CTR_HEADER
#define CTR_HEADER

#include <string>
#include "cbc.h"

int ctr_encrypt(unsigned char *key, unsigned char *text, unsigned int N, u_string &output);
int ctr_decrypt(unsigned char *key, unsigned char *text, unsigned int N, u_string &output);

#endif
