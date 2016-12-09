# cosc483-pa23-4
## Information
We assumed that there would always be an even number of hex characters.

## Key generation
Key generation is done the same way as PA2 except for the introduction of an identity and a signature. To self-sign, enter None for the signature private key. To sign with another person's private key enter that person's private key file name.

Key generation produces a private key file (with no file extension name), a .pub file, a .hex file (hex encoded public file), and a .sig file (the signature of the pub file).

To verify the public kye file with the signature use the sign executable to verify with the public key file of the signing authority, the hex encoded public key file, and the sig file. 


## Signing
The executable sign is used to sign and verify files. In order to sign a file you need a private key file to sign with, a hex encoded file to sign, and an output file to store the sig file (stored as a .sig file).

To verify a file, you need a public key file (the public key file of the key you used to sign with), the hex encoded file that was originally signed, and the signature file (ending in a .sig file).


