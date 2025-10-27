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

//Empezamos con los algoritmos de descifrado AES ECB
//Tienes que saber que AES 128 trabaja siempre con 16 bytes, que utiliza matrces de 4x4, se usa 10 rondas de cifrado/descifrado con
// 4 transformaciones principales: SubBytes, ShiftRows, MixColumns y AddRoundKey.

//El AES 128 tiene varias formas, ahora hablamos del ECB (Electronic Code Book) que es el modo mas sencillo de todos.
//Sencillo si, pero no es el mas seguro, ya que si tenemos bloques iguales en el texto plano,
//estos se cifran en bloques iguales en el texto cifrado, lo que puede dar pistas al atacante.

//Y pq te preguntas? Pues pq en este modo, cada bloque de 16 bytes se cifra de forma independiente,
//sin tener en cuenta los bloques anteriores o posteriores. ECB ES DETERMINISTA.

//Al igual que todo algoritmo pues tienes siempre el texto que quieres cifrar/descifrar y la clave con la que lo haces.
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