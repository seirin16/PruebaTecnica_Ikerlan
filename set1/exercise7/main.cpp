#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "tools.h"
#include "tools_cpp.h"

//-----------------------------------------------------------------------------------------------------------------
// Enunciado del ejercicio 7: AES in ECB mode

// The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

// "YELLOW SUBMARINE".

// (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

// Decrypt it. You know the key, after all.

// Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
// Do this with code.

// You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.

//------------------------------------------------------------------------------------------------------------------

int main()
{
    std::ifstream file("/home/seirin16/pruebaIkerlan/PruebaTecnica_Ikerlan/set1/exercise7/file2.txt");
    std::stringstream ss;
    ss << file.rdbuf();
    std::string base64_data = ss.str();

    std::vector<unsigned char> ciphertext = base64_to_bytes(base64_data);

    const unsigned char *key = (const unsigned char *)"YELLOW SUBMARINE";

    std::vector<unsigned char> plaintext = aes_ecb_decrypt(ciphertext, key);

    std::cout << std::string(plaintext.begin(), plaintext.end()) << "\n";

    return 0;
}