/* Header for locking function
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#ifndef ENCRYPT_DIR_LOCK_HEADER
#define ENCRYPT_DIR_LOCK_HEADER

#include <string>
#include "encrypt_dir.h"

#define SYM_KEY_SIZE 32

typedef unsigned char UCHAR;

bool verify_rsa_key(Rsa_key &key, std::string &cert_auth, std::string dir);

bool lock_dir(std::string &dir, Rsa_key &locking, Rsa_key &unlocking);

#endif
