/* Header file
 * Had to add this for part 3
 *
 * Tyler Stuessi
 * Jeremy Herwig
 */

#ifndef ENCRYPT_HEADER
#define ENCRYPT_HEADER

#include <string>

int encrypt_or_decrypt(std::string mode, std::string action, std::string keyfile, std::string textfile, std::string outputfile);

#endif
