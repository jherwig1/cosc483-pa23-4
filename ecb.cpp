#include <string>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#define ABORT() (fprintf(stderr, "%s\nAborting in %s at %s:%d\n", ERR_error_string(ERR_get_error(), NULL), __PRETTY_FUNCTION__, __FILE__, __LINE__), abort(), 0)

typedef std::basic_string<unsigned char> u_string;
extern u_string encode(u_string key, u_string data);
extern u_string decode(u_string key, u_string data);
// echo -n "1234567890uvwxyz" | openssl aes-128-ecb -K $(echo -n "a_key_simple_key" | xxd -ps) -nopad | xxd
// echo "142f 7d9e ad8c 0682 30e0 f165 a52f f789" | xxd -r -ps | openssl aes-128-ecb -d -K $(echo -n "a_key_simple_key" | xxd -ps) -nopad

/*
int main()
{
  SSL_load_error_strings();

  u_string key = (unsigned char *) "a_key_simple_key";
  u_string clear_text = (unsigned char *) "1234567890uvwxyz";
  u_string secret_txt = (unsigned char *) "\x14\x2f" "\x7d\x9e" "\xad\x8c" "\x06\x82" "\x30\xe0" "\xf1\x65" "\xa5\x2f" "\xf7\x89";

  std::cerr << "ENCODING: " << (encode(key, clear_text)==secret_txt ? "ok" : "FAIL") << std::endl;
  std::cerr << "ENCODING: " << (char*)clear_text.c_str() << " --> " << (char*)encode(key, clear_text).c_str() << std::endl;
  std::cerr << "DECODING: " << (decode(key, secret_txt)==clear_text ? "ok" : "FAIL") << std::endl;
  std::cerr << "DECODING: " << (char*)secret_txt.c_str() << " --> " << (char*)decode(key, secret_txt).c_str() << std::endl;

  return 0;
}
*/
extern  u_string encode(u_string key, u_string data)
{
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);
  EVP_EncryptInit_ex (&ctx, EVP_aes_128_ecb(), NULL, key.c_str(), NULL);
  EVP_CIPHER_CTX_set_padding(&ctx, false);
  unsigned char buffer[1024], *pointer = buffer;
  int outlen;
  EVP_EncryptUpdate (&ctx, pointer, &outlen, data.c_str(), data.length()) or ABORT();
  pointer += outlen;
  EVP_EncryptFinal_ex(&ctx, pointer, &outlen) or ABORT();
  pointer += outlen;
  return u_string(buffer, pointer-buffer);
}

extern u_string decode(u_string key, u_string data)
{
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);
  EVP_DecryptInit_ex (&ctx, EVP_aes_128_ecb(), NULL, key.c_str(), NULL);
  EVP_CIPHER_CTX_set_padding(&ctx, false);
  unsigned char buffer[1024], *pointer = buffer;
  int outlen;
  EVP_DecryptUpdate (&ctx, pointer, &outlen, data.c_str(), data.length()) or ABORT();
  pointer += outlen;
  EVP_DecryptFinal_ex(&ctx, pointer, &outlen) or ABORT();
  pointer += outlen;
  return u_string(buffer, pointer-buffer);
}
