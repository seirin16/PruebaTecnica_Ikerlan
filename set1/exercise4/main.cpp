#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <algorithm>

#include "tools.h"

//-----------------------------------------------------------------------------------------------------------------
// Enunciado del ejercicio 4: Detect single-character XOR

// One of the 60-character strings in this file has been encrypted by single-character XOR.

// Find it.

// (Your code from #3 should help.)

//------------------------------------------------------------------------------------------------------------------

//Es basicamente lo mismo que el ejercicio 3, pero ahora tenemos que probar con cada linea del fichero,
//y quedarnos con la que nos de la mejor puntuacion.

//Destacar que aqui paso a C++ ya que es mucho más facil manejar ficheros y strings que en C puro.

int main()
{
    std::ifstream file("/home/seirin16/pruebaIkerlan/PruebaTecnica_Ikerlan/set1/exercise4/file.txt");
    if (!file)
    {
        std::cerr << "No se pudo abrir file.txt\n";
        return 1;
    }
    std::string line;

    int best_score = -1;
    std::string best_plain;
    unsigned char best_key = 0;

    while (std::getline(file, line)) // Leer cada linea del fichero
    {
        size_t len;
        unsigned char *message = hex_to_bytes(line.c_str(), &len);

        for (int k = 0; k < 256; k++) // Probar todas las claves posibles (0-255)
        {
            unsigned char key = static_cast<unsigned char>(k);
            unsigned char *response = xor_key(message, len, &key, 1); // XOR con la clave de un solo byte

            int score = getScore(response, len);

            if (score > best_score)
            {
                best_score = score;
                best_key = key;

                best_plain = std::string(reinterpret_cast<char *>(response), len);
            }
        }
    }

    std::cout << "Mejor clave: 0x" << std::hex << (int)best_key << std::dec
              << " ('" << (isprint(best_key) ? (char)best_key : '?') << "')\n";
    std::cout << "Plaintext descifrado:\n"
              << best_plain << "\n";
    std::cout << "Puntuación: " << best_score << "\n";

    return 0;
}