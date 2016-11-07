/* This file converts the weird hex thing to bytes and
 * vice versus
 */

#include <string>
#include <iostream>
#include <iomanip>
#include <cstdio>
#include "hex_string_conv.h"

typedef unsigned char UCHAR;
typedef unsigned int UINT;

using namespace std;

void hex_to_binary(string text, UCHAR *output, UINT N) {
	int i;
	string temp;

	temp = "";
	for(i = 0; i < N; i++) {
		temp += text[2*i];
		temp += text[2*i+1];
		output[i] = stoul(temp, NULL, 16);
		temp = "";
	}
}

void binary_to_hex(UCHAR *text, UINT N, string& output) {
	int i;
	char temp[3];

	output = "";

	for(i = 0; i < N; i++) {
		sprintf(temp, "%02x", text[i]);
		output += temp;
	}
}
