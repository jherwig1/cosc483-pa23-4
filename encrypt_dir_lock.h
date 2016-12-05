/* Header for locking function
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#ifndef ENCRYPT_DIR_LOCK_HEADER
#define ENCRYPT_DIR_LOCK_HEADER

#include <string>
#include "encrypt_dir.h"

bool lock_dir(std::string &dir, Rsa_key &locking, Rsa_key &unlocking);

#endif
