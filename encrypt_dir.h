/*This holds some of the nicer structs and such
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#ifndef ENCRYPT_DIR_HEADER
#define ENCRYPT_DIR_HEADER

#define LOCK "lock"
#define UNLOCK "unlock"

#include <string>

struct Rsa_key {
	std::string private_keyfile;
	std::string public_keyfile;
	std::string public_sigfile;
};

#endif
