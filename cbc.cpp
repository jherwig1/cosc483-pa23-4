#include <iostream>
#include <openssl/rand.h>
#include "cbc.h"

using namespace std;

void block_xor(unsigned char *a, unsigned char *b, unsigned char *out) {
	int i;
	for (i = 0; i < BLOCK_SIZE; i++)
		out[i] = a[i] ^ b[i];
}

int cbc_encrypt(unsigned char *key, unsigned char *text, unsigned int N,  u_string &output) {
	int i;
	unsigned char IV[BLOCK_SIZE];
	unsigned char cipher[BLOCK_SIZE];
	unsigned int pN, num_blocks;
	unsigned char block[BLOCK_SIZE];
	unsigned char *pad;
	u_string ret;

	/* Seed the random number gen and get the IV */
	RAND_poll();
	RAND_pseudo_bytes(IV, sizeof(IV));

	/* Compute the number of bytes needed to pad to block size */
	pN = 0;
	if (N % BLOCK_SIZE)
		pN = BLOCK_SIZE - N % BLOCK_SIZE;

	/* Compute the number of blocks for the message */
	num_blocks = (N + pN) / BLOCK_SIZE;

	if (DEBUG) {
		cout << "num blocks = " << num_blocks << endl;
		cout << "pN = " << pN << endl;
	}

	output.resize((num_blocks + 2) * BLOCK_SIZE);
	memcpy(cipher, IV, BLOCK_SIZE);

	/* Do the CBC on each block, xor the result of the prev. in with the plaintext*/
	for (i = 0; i < num_blocks; i++) {

		if ( (i * BLOCK_SIZE + BLOCK_SIZE) > N) {
			if (DEBUG) {
				cout << "creating a pad, copying " <<
					(i + 1) * BLOCK_SIZE - N << " bytes into pad\n";
			}
			pad = (unsigned char *) calloc(sizeof(unsigned char), BLOCK_SIZE);
			memcpy(pad, (text + i * BLOCK_SIZE), ( (i+1) * BLOCK_SIZE) - N);
			block_xor(cipher, pad, block);
		} else
			block_xor(cipher, (text + i * BLOCK_SIZE), block);

		/* TODO: this could be the issue */
		u_string block_s(block);
		block_s.resize(BLOCK_SIZE);

		ret = encode(key, block_s);
		memcpy(cipher, ret.c_str(), BLOCK_SIZE);
		memcpy(&(output[i*BLOCK_SIZE]), cipher, BLOCK_SIZE);
	}

	/* Now we add a BLOCK_SIZE bit block to the end */
	output[num_blocks * BLOCK_SIZE + (BLOCK_SIZE - 1)] = pN;

	/* Copy the IV */
	for (i = 0; i < BLOCK_SIZE; i++) {
		output[(num_blocks + 1) * BLOCK_SIZE + i] = IV[i];
	}

	fwrite(output.c_str(), 1, (num_blocks + 2) * BLOCK_SIZE, stdout);
	free(pad);
	//cout << "output size is: " << output.size() << endl;
	//fwrite(output.c_str(), 1, output.size(), stdout);
	return (num_blocks + 1) * BLOCK_SIZE;
}

void cbc_decrypt(unsigned char *key, unsigned char *text, int N, u_string &output) {
	unsigned int num_blocks;
	unsigned char IV[BLOCK_SIZE];
	unsigned int pN;
	unsigned char prev_block[BLOCK_SIZE];
	unsigned char cur_block[BLOCK_SIZE];
	unsigned char *ptr;
	unsigned char out[BLOCK_SIZE];
	unsigned char block[BLOCK_SIZE];
	
	u_string ret;
	int i;
	pN = 0;

	/* Compute the number of blocks and the number of bytes of padding */
	num_blocks = N / BLOCK_SIZE;
	cout << "num blocks = " << num_blocks << endl;
	pN = text[(num_blocks - 1) *BLOCK_SIZE - 1];
	cout << "pN = " << pN << endl;

	/* Grab the IV from the end of the input text */
	memcpy(IV, (text + (num_blocks - 1) * BLOCK_SIZE), BLOCK_SIZE);
	output.resize((num_blocks - 2) * BLOCK_SIZE - pN);

	for (i = num_blocks - 2; i >= 0; i--) {
		if (i == 0)
			ptr = IV;
		else {
			memcpy(prev_block, (text + (i - 1) * BLOCK_SIZE), BLOCK_SIZE);
			ptr = prev_block;
		}

		memcpy(block, text + i * BLOCK_SIZE, BLOCK_SIZE);
		u_string block_s(block);
		block_s.resize(BLOCK_SIZE);
		ret = decode(key, block_s);
		memcpy(cur_block, ret.c_str(), BLOCK_SIZE);
		block_xor(ptr, cur_block, out);
		fwrite(out, 1, BLOCK_SIZE, stdout);
		int j;

		for (j = 0; j < BLOCK_SIZE; j++) {
			output[i * BLOCK_SIZE + j] = out[j];
		}
	}

	printf("%s\n", output.c_str());
}
