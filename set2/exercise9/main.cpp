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
// Enunciado del ejercicio 9: Implement PKCS#7 padding

// A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

// One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

// So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

// "YELLOW SUBMARINE"

// ... padded to 20 bytes would be:

// "YELLOW SUBMARINE\x04\x04\x04\x04"

//------------------------------------------------------------------------------------------------------------------

int main()
{
    std::string msg = "YELLOW SUBMARINE";
    std::vector<unsigned char> input(msg.begin(), msg.end());
    auto padded = pkcs7_pad(input, 20);

    for (unsigned char c : padded)
    {
        std::cout << std::hex << std::uppercase << (int)c << " ";
    }

    return 0;
}