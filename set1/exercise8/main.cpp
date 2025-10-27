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

//Lo dicho en el anterior ejercicio, el problema de ECB es que es determinista, por lo que si un bloque de 16 bytes se repite en el texto plano, el bloque cifrado correspondiente tambien se repetira.
//Por lo tanto, para detectar si un texto ha sido cifrado con ECB, basta con contar cuantas veces se repite cada bloque de 16 bytes en el texto cifrado.
//Si un texto tiene muchos bloques repetidos, es muy probable que haya sido cifrado con ECB.

//Tengo que suponer que la linea encriptada es lo suficientemente larga para que esta se divida en B0 B1 B2 B3 B4... y 
//que excatamente tenga el mismo contenido para que por ejemplo B0 y B3 coincidad y saber que es ECB 

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
        for (int i = 0; i < num_blocks; i++) // Recorremos cada bloque
        {
            for (int j = i + 1; j < num_blocks; j++) // Comparamos con los bloques siguientes
            {
                if (std::memcmp(ciphertext + i * block_size, ciphertext + j * block_size, block_size) == 0) // Si los bloques son iguales
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