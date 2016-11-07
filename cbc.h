#ifndef CBC_HEADER
#define CBC_HEADER

#define BLOCK_SIZE 16
#define DEBUG 0

typedef std::basic_string<unsigned char> u_string;
extern u_string encode(u_string key, unsigned char *data);
extern u_string decode(u_string key, unsigned char *data);

void block_xor(unsigned char *a, unsigned char *b, unsigned char *out);

int cbc_encrypt(unsigned char *key, unsigned char *text, unsigned int N,  u_string &output);

int cbc_decrypt(unsigned char *key, unsigned char *text, int N, u_string &output);

#endif
