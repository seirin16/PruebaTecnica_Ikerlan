#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <ctime>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <set>
#include <map>

#include "tools.h"
#include "tools_cpp.h"

//-----------------------------------------------------------------------------------------------------------------
// Enunciado del ejercicio 12: Byte-at-a-time ECB decryption (Simple)

// Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

// Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

// Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
// aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
// dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
// YnkK

// Spoiler alert.

// Do not decode this string now. Don't do it.

// Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

// What you have now is a function that produces:

// AES-128-ECB(your-string || unknown-string, random-key)

// It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

// Here's roughly how:

//     Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
//     Detect that the function is using ECB. You already know, but do this step anyways.
//     Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
//     Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
//     Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
//     Repeat for the next byte.

// Congratulations.

// This is the first challenge we've given you whose solution will break real crypto. Lots of people know that when you encrypt something in ECB mode, you can see penguins through it. Not so many of them can decrypt the contents of those ciphertexts, and now you can. If our experience is any guideline, this attack will get you code execution in security tests about once a year.

//------------------------------------------------------------------------------------------------------------------

// El truco está en alinear tu input para que el byte secreto "caiga" en el final de un bloque, y luego mapearlo
// contra un diccionario de posibles encriptaciones

// Idea clave: Inputs crecientes ("A", "AA", "AAA"...) para "empujar" el unknown_string hacia posiciones predecibles en los bloques.
// Crea un input que deje exactamente 1 byte vacío al final del bloque donde cae el byte i (usando padding de 'A's).
// 12345678 9

// Paso 0: Byte 0 ('1')
// Referencia:  AAAAAAAT TTTTTTTT
// Diccionario: AAAAAAAx TTTTTTTT T → Coincide cuando x='1'
// Paso 1: Byte 1 ('2')
// Referencia:  AAAAAA1T TTTTTTT
// Diccionario: AAAAAA1x TTTTTTTT → Coincide cuando x='2'
// Paso 2: Byte 2 ('3')
// Referencia:  AAAAA12T TTTTTT
// Diccionario: AAAAA12x TTTTTTT → Coincide cuando x='3'
// Paso 3: Byte 3 ('4')
// Referencia:  AAAA123T TTTTT
// Diccionario: AAAA123x TTTTTT → Coincide cuando x='4'
// Paso 4: Byte 4 ('5')
// Referencia:  AAA1234T TTTT
// Diccionario: AAA1234x TTTTT → Coincide cuando x='5'
// Paso 5: Byte 5 ('6')
// Referencia:  AA12345T TTT
// Diccionario: AA12345x TTTT → Coincide cuando x='6'
// Paso 6: Byte 6 ('7')
// Referencia:  A123456T TT
// Diccionario: A123456x TTT → Coincide cuando x='7'
// Paso 7: Byte 7 ('8')
// Referencia:  1234567T T
// Diccionario: 1234567x TT → Coincide cuando x='8'
// Paso 8: Byte 8 ('9') – Salto a bloque 1
// Referencia:  AAAAAAA1 2345678T (en bloque 1)
// Diccionario: AAAAAAA1 2345678x T → Coincide cuando x='9' (bloque 1 simulado con known)
namespace
{
    const char *UNKNOWN_B64 =
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        "YnkK";

    std::vector<unsigned char> GLOBAL_KEY = generate_random_key();
    std::vector<unsigned char> UNKNOWN_BYTES = base64_to_bytes(UNKNOWN_B64);
}

std::vector<unsigned char> ecb_oracle(const std::vector<unsigned char> &input)
{
    std::vector<unsigned char> full = input;
    full.insert(full.end(), UNKNOWN_BYTES.begin(), UNKNOWN_BYTES.end());
    return aes_ecb_encrypt(full, GLOBAL_KEY.data());
}

int detect_block_size()
{
    size_t initial_size = ecb_oracle({}).size();
    for (int i = 1; i < 128; ++i)
    {
        std::vector<unsigned char> input(i, 'A');
        size_t new_size = ecb_oracle(input).size();
        if (new_size > initial_size)
        {
            return new_size - initial_size;
        }
    }
    return -1;
}

std::vector<unsigned char> decrypt_ecb_unknown_string(int block_size)
{
    std::vector<unsigned char> known;         // Bytes descifrados acumulados.
    size_t total_len = ecb_oracle({}).size(); // Longitud total del unknown (en bytes, sin padding).

    for (size_t i = 0; i < total_len; ++i) 
    {                                        // Por cada byte a adivinar (i=0 a len-1).
        size_t block_index = i / block_size; // ¿En qué bloque cae este byte? (ej: i=0 → block 0).

        // Padding para que el byte i caiga JUSTO al final del bloque (1 byte corto).
        size_t pad_len = block_size - (i % block_size) - 1; // Ej: Si i%16=0, pad_len=15 ('A's para llenar 15, +1 byte secreto).
        std::vector<unsigned char> input(pad_len, 'A');     // Input: pad_len 'A's.
        auto reference = ecb_oracle(input);                 // CT: [bloques previos] + [bloque con 'A's + byte_i_del_unknown al final].

        // Diccionario: 256 entradas, cada una un posible "último byte".
        std::map<std::vector<unsigned char>, unsigned char> dict;
        for (int b = 0; b < 256; ++b)
        {
            std::vector<unsigned char> trial = input;              // Copia el padding.
            trial.insert(trial.end(), known.begin(), known.end()); // + bytes ya conocidos (para bytes siguientes en el bloque).
            trial.push_back(static_cast<unsigned char>(b));        // + byte de prueba (0-255).

            auto encrypted = ecb_oracle(trial); // Cifra: el último bloque será [padding + known + b], que en PT coincide posición con el secreto.
            // Extrae JUSTO ese bloque del CT.
            std::vector<unsigned char> block(encrypted.begin() + block_index * block_size,
                                             encrypted.begin() + (block_index + 1) * block_size);
            dict[block] = static_cast<unsigned char>(b); // Mapea CT_bloque → b.
        }

        // Extrae el bloque "referencia" (con el secreto real al final).
        std::vector<unsigned char> target_block(reference.begin() + block_index * block_size,
                                                reference.begin() + (block_index + 1) * block_size);

        if (dict.count(target_block))
        { // ¿Coincide con algún b? Sí → ese es el byte secreto.
            known.push_back(dict[target_block]);
        }
        else
        {
            break; // Fin del unknown (no más coincidencias).
        }
    }
    return known;
}

int main()
{
    std::srand(std::time(nullptr));

    int block_size = detect_block_size();
    std::cout << "Block size detectado: " << block_size << "\n";

    if (detect_mode(ecb_oracle(std::vector<unsigned char>(64, 'A'))) != "ECB")
    {
        std::cerr << "El oracle no usa ECB, abortando.\n";
        return 1;
    }

    auto decrypted = decrypt_ecb_unknown_string(block_size);
    std::string result(decrypted.begin(), decrypted.end());

    std::cout << "Mensaje descifrado:\n"
              << result << "\n";

    return 0;
}