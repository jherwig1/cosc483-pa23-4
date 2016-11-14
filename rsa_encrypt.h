#ifndef __RSA_ENCRYPT__
#define __RSA_ENCRYPT__

/* RSA Encryption
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#include <string>

typedef unsigned char UCHAR;

void rsa_encrypt(std::string &keyfile, std::string &inputfile, std::string &outputfile);

#endif
