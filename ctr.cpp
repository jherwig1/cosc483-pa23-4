/* CTR AES Mode
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <iostream>
#include <string.h>
#include <openssl/rand.h>
#include "ctr.h"
#include "cbc.h"

typedef unsigned char UCHAR;
typedef unsigned int UINT;

using namespace std;

int ctr_encrypt(UCHAR *key, UCHAR *text, UINT N, u_string &output) {
	UCHAR IV[BLOCK_SIZE];
	UCHAR orig_iv[BLOCK_SIZE];
	UCHAR iv_encrypt[BLOCK_SIZE];
	UCHAR cipher[BLOCK_SIZE];
	UCHAR last_block[BLOCK_SIZE];
	UCHAR block[BLOCK_SIZE];
	UINT num_blocks;
	int i;
	u_string ret;


	//Seed the RNG and get the IV
	RAND_poll();
	RAND_pseudo_bytes(IV, sizeof(IV));
	memcpy(orig_iv, IV, BLOCK_SIZE);

	//Get the number of blocks
	//If N % BLOCK_SIZE == 0 (ie BLOCK_SIZE divides N
	//this will still be right, as you have to add an
	//additional block of padding
	num_blocks = N / BLOCK_SIZE  + 1;
	output.resize((num_blocks+1)*BLOCK_SIZE);

	//compute the number of bytes of padding for the message
	//If N % BLOCK_SIZE is 0, then we have to add another block
	if (N % BLOCK_SIZE == 0) {
		for (i = 0; i < BLOCK_SIZE; i++) {
			last_block[i] = BLOCK_SIZE;
		}
	} else {
		memcpy((void *)last_block, text + (num_blocks-1)*BLOCK_SIZE, N % BLOCK_SIZE);
		for(i = N % BLOCK_SIZE; i < BLOCK_SIZE; i++) {
			last_block[i] = BLOCK_SIZE - N % BLOCK_SIZE;
		}
	}

	//Go through the actual encryption
	//for every block except the last block
	for(i = 0; i < num_blocks-1; i++) {
		//increment the counter and send it through the encryption
		//I am using the last sizeof(UINT) bytes of the IV as the counter
		//If I reach the cap, it will cylce around
		(*((UINT *)(IV + BLOCK_SIZE - sizeof(UINT))))++;
		ret = encode(key, IV);

		//copy encrpyted counter into buffer and xor it with text
		memcpy(iv_encrypt, ret.c_str(), BLOCK_SIZE);
		block_xor(iv_encrypt, text + i*BLOCK_SIZE, cipher);

		//copy it into output
		memcpy(&(output[i*BLOCK_SIZE]), cipher, BLOCK_SIZE);
	}

	//handle the last block
	(*((UINT *)(IV + BLOCK_SIZE - sizeof(UINT))))++;
	ret = encode(key, IV);

	memcpy(iv_encrypt, ret.c_str(), BLOCK_SIZE);
	block_xor(iv_encrypt, last_block, cipher);

	memcpy(&(output[i*BLOCK_SIZE]), cipher, BLOCK_SIZE);

	//tack on the IV at the end
	i++;
	memcpy(&(output[i*BLOCK_SIZE]), orig_iv, BLOCK_SIZE);

	return (num_blocks+1)*BLOCK_SIZE;
}

int ctr_decrypt(UCHAR *key, UCHAR *text, UINT N, u_string &output) {
	UCHAR temp[BLOCK_SIZE];
	UCHAR IV[BLOCK_SIZE];
	UCHAR iv_encrypt[BLOCK_SIZE];
	UCHAR *plaintext;
	UINT num_blocks;
	UINT num_padded;
	int i;
	u_string ret;

	num_blocks = N / BLOCK_SIZE;
	plaintext = (UCHAR *)malloc((num_blocks-1)*BLOCK_SIZE);

	//the IV is stored in the last block
	memcpy(IV, text + (num_blocks-1)* BLOCK_SIZE, BLOCK_SIZE);
	
	//go through and encode the counter and XOR it with
	//the ciphertext
	for(i = 0; i < num_blocks - 1; i++) {
		(*((UINT *)(IV + BLOCK_SIZE - sizeof(UINT))))++;
		ret = encode(key, IV);

		//copy encrpyted counter into buffer and xor it with text
		memcpy(iv_encrypt, ret.c_str(), BLOCK_SIZE);
		block_xor(iv_encrypt, text + i*BLOCK_SIZE, temp);

		//copy to temporary buffer
		memcpy(plaintext + i*BLOCK_SIZE, temp, BLOCK_SIZE);
	}

	//look at the last byte for the number of bytes padded
	//here I could check to make sure that everything is fine
	//since I padded with the number of bytes, but we are assuming
	//that the input will be valid and not corrupted
	num_padded = plaintext[(num_blocks-1)*BLOCK_SIZE - 1];

	//copy all the input up to the padding into the output vector
	output.resize((num_blocks-1)*BLOCK_SIZE-num_padded);
	for(i = 0; i < (num_blocks-1)*BLOCK_SIZE-num_padded; i++) {
		output[i] = plaintext[i];
	}

	free(plaintext);
	return (num_blocks-1)*BLOCK_SIZE-num_padded;
}







