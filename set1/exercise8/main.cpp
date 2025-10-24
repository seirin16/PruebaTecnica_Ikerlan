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
// Enunciado del ejercicio 8: Detect AES in ECB mode

// In this file are a bunch of hex-encoded ciphertexts.

// One of them has been encrypted with ECB.

// Detect it.

// Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.

//------------------------------------------------------------------------------------------------------------------

int main()
{
    std::ifstream file("/home/seirin16/pruebaIkerlan/PruebaTecnica_Ikerlan/set1/exercise8/file3.txt");
    if (!file)
    {
        std::cerr << "No se pudo abrir file3.txt\n";
        return 1;
    }
    std::string line;

    int max_repetitions = 0;
    std::string ecb_candidate;
    while (std::getline(file, line))
    {
        size_t len;
        unsigned char *ciphertext = hex_to_bytes(line.c_str(), &len);

        int block_size = 16;
        int num_blocks = len / block_size;

        int repetitions = 0;
        for (int i = 0; i < num_blocks; i++)
        {
            for (int j = i + 1; j < num_blocks; j++)
            {
                if (std::memcmp(ciphertext + i * block_size, ciphertext + j * block_size, block_size) == 0)
                {
                    repetitions++;
                }
            }
        }

        if (repetitions > max_repetitions)
        {
            max_repetitions = repetitions;
            ecb_candidate = line;
        }

        free(ciphertext);
    }
    std::cout << "Línea con posible ECB: " << ecb_candidate << "\n";

    return 0;
}