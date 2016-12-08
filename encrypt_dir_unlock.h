#ifndef ENCRYPT_DIR_UNLOCK_HEADER
#define ENCRYPT_DIR_UNLOCK_HEADER

#include <string>
#include "encrypt_dir.h"

bool unlock_dir(std::string &dir, Rsa_key &unlocking);

#endif
