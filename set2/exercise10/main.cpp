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
// Enunciado del ejercicio 10: Implement CBC mode

// CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

// In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

// The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

// Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

// The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
// Don't cheat.

// Do not use OpenSSL's CBC code to do CBC mode, even to verify your results. What's the point of even doing this stuff if you aren't going to learn from it?

//------------------------------------------------------------------------------------------------------------------

// Ahora tenemos un modo nuevo modo, que es el CBC.
// Lo mas importante es que tenemos que ir guardando el bloque cifrado anterior para hacer el XOR con el siguiente bloque descifrado.

//PARA DESCIFRAR EN CBC:
//En otras palabras si tenemos C0 C1 C2 C3... y P0 P1 P2 P3...
//Para obtener P0 hacemos D(C0) XOR IV
//Para obtener P1 hacemos D(C1) XOR C0
//Para obtener P2 hacemos D(C2) XOR C1
//Y asi sucesivamente... Usamos el bloque anterior para cifrar el siguiente bloque

//PARA CIFRAR EN CBC:
//En otras palabras, si tenemos P0 P1 P2 P3... e IV, y queremos generar C0 C1 C2 C3...
//Para obtener C0 hacemos E(P0) XOR IV
//Para obtener C1 hacemos E(P1) XOR C0
//Para obtener C2 hacemos E(P2) XOR C1
//Y así sucesivamente... Usamos el bloque cifrado anterior para el siguiente bloque plano.

int main()
{
    std::ifstream file("/home/seirin16/pruebaIkerlan/PruebaTecnica_Ikerlan/set2/exercise10/file4.txt");
    std::stringstream ss;
    ss << file.rdbuf();
    std::string base64_data = ss.str();

    std::vector<unsigned char> ciphertext = base64_to_bytes(base64_data);

    const unsigned char *key = (const unsigned char *)"YELLOW SUBMARINE";
    std::vector<unsigned char> iv(16, 0x00);

    std::vector<unsigned char> plaintext = aes_cbc_decrypt(ciphertext, key, iv);

    std::cout << std::string(plaintext.begin(), plaintext.end()) << "\n";

    return 0;
}