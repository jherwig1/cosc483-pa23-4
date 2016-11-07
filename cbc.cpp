#include <iostream>
#include <string.h>
#include <openssl/rand.h>
#include "cbc.h"

using namespace std;

void block_xor(unsigned char *a, unsigned char *b, unsigned char *out) {
	int i;
	for (i = 0; i < BLOCK_SIZE; i++)
		out[i] = a[i] ^ b[i];
}

int cbc_encrypt(unsigned char *key, unsigned char *text, unsigned int N,  u_string &output, unsigned char *IV) {
	int i;
//	unsigned char IV[BLOCK_SIZE];
	unsigned char cipher[BLOCK_SIZE];
	unsigned int pN, num_blocks;
	unsigned char block[BLOCK_SIZE];
	unsigned char *pad = NULL;
	u_string ret;


	if (IV == NULL) {
		IV = (unsigned char *) malloc(sizeof(unsigned char) * BLOCK_SIZE);
		/* Seed the random number gen and get the IV */
		RAND_poll();
		RAND_pseudo_bytes(IV, sizeof(IV));
	}

	/* Compute the number of bytes needed to pad to block size */
	pN = 0;

	if (N % BLOCK_SIZE)
		pN = BLOCK_SIZE - N % BLOCK_SIZE;

	/* Compute the number of blocks for the message */
	num_blocks = (N + pN) / BLOCK_SIZE;

	output.resize((num_blocks + 2) * BLOCK_SIZE);
	memcpy(cipher, IV, BLOCK_SIZE);

	/* Do the CBC on each block, xor the result of the prev. in with the plaintext*/
	for (i = 0; i < num_blocks; i++) {
		if ( (i * BLOCK_SIZE + BLOCK_SIZE) > N) {
			pad = (unsigned char *) calloc(sizeof(unsigned char), BLOCK_SIZE);
			memcpy(pad, (text + i * BLOCK_SIZE), BLOCK_SIZE - pN);
			block_xor(cipher, pad, block);
		} else
			block_xor(cipher, (text + i * BLOCK_SIZE), block);

		ret = encode(key, block);
		memcpy(cipher, ret.c_str(), BLOCK_SIZE);
		memcpy(&(output[i*BLOCK_SIZE]), cipher, BLOCK_SIZE);
	}

	/* Now we add a BLOCK_SIZE bit block to the end */
	output[num_blocks * BLOCK_SIZE + (BLOCK_SIZE - 1)] = pN;

	/* Copy the IV */
	for (i = 0; i < BLOCK_SIZE; i++) {
		output[(num_blocks + 1) * BLOCK_SIZE + i] = IV[i];
	}

	// TODO
	//fwrite(output.c_str(), 1, (num_blocks + 2) * BLOCK_SIZE, stdout);

	if (pad != NULL)
		free(pad);
	return (num_blocks + 2) * BLOCK_SIZE;
}

int cbc_decrypt(unsigned char *key, unsigned char *text, int N, u_string &output) {
	unsigned int num_blocks;
	unsigned char IV[BLOCK_SIZE];
	unsigned int pN;
	unsigned char prev_block[BLOCK_SIZE];
	unsigned char cur_block[BLOCK_SIZE];
	unsigned char *ptr;
	unsigned char out[BLOCK_SIZE];
	unsigned char block[BLOCK_SIZE];
	
	u_string ret;
	int i, k, size;
	int j;
	pN = 0;

	/* Compute the number of blocks and the number of bytes of padding */
	num_blocks = N / BLOCK_SIZE;
	pN = text[(num_blocks - 1) * BLOCK_SIZE - 1];

	/* Grab the IV from the end of the input text */
	memcpy(IV, (text + (num_blocks - 1) * BLOCK_SIZE), BLOCK_SIZE);
	output.resize((num_blocks - 2) * BLOCK_SIZE - pN);

	size = BLOCK_SIZE - pN;

	for (i = num_blocks - 3, k = 0; i >= 0; i--, k++) {
		if (i == 0) 
			ptr = IV;
		else {
			memcpy(prev_block, (text + (i - 1) * BLOCK_SIZE), BLOCK_SIZE);
			ptr = prev_block;
		}

		memcpy(block, text + i * BLOCK_SIZE, BLOCK_SIZE);
		ret = decode(key, block);

		for (j = 0; j < BLOCK_SIZE; j++)
			cur_block[j] = ret[j];

		block_xor(ptr, cur_block, out);
/*
		for (j = 0; j < BLOCK_SIZE; j++)
			output[i * BLOCK_SIZE + j] = out[j];
*/
		memcpy(&(output[i * BLOCK_SIZE]), out, BLOCK_SIZE);
		size = BLOCK_SIZE;
	}

//	printf("%s\n", output.c_str());
	return (num_blocks - 2) * BLOCK_SIZE - pN;
}

int cbc_mac_verify(unsigned char *key, unsigned char *text, unsigned int N, string tagfile) {

	/* Verify takes a tag and checks if hte tag verifeis */
	u_string output;
	int Nret;

	Nret = cbc_mac(key, text, N, output);
	cout << "verified the tag for the file, Nret = " << Nret << endl;
}


int cbc_mac_generate(unsigned char *key, unsigned char *text, unsigned int N, string tagfile) {
	/* Generate gets a tag and runs it through */
	u_string output;
	int Nret;

	Nret = cbc_mac(key, text, N, output);
	cout << "Generated the tag for the file, Nret = " << Nret << endl;

	/* Write the key out to the file */
}

int cbc_mac(unsigned char *key, unsigned char *text, unsigned int N, u_string output) {
	unsigned char *IV = (unsigned char *) calloc(sizeof(unsigned char), BLOCK_SIZE);
	int Ne;
	unsigned char *plaintext = (unsigned char *) malloc(BLOCK_SIZE + N);
	plaintext[0] = N;
	memcpy((plaintext + BLOCK_SIZE), text, N);
	Ne = cbc_encrypt(key, plaintext, N, output, IV);
	return Ne;

}

