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
// Enunciado del ejercicio 14: Byte-at-a-time ECB decryption (Harder)

// Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

// AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

// Same goal: decrypt the target-bytes.
// Stop and think for a second.

// What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

// Think "STIMULUS" and "RESPONSE".

//------------------------------------------------------------------------------------------------------------------

//Ahora el oráculo añade un prefijo random de longitud variable (random-prefix || tu-input || unknown), lo que "desalinea" todo 
//y oculta el unknown. El truco es detectar primero la longitud del prefijo (usando "STIMULUS-RESPONSE": 
//envías conjunto de 'A's crecientes y buscas repeticiones de bloques idénticos para inferir dónde empieza tu control). 
//Luego, adaptas el ataque byte-at-a-time "saltando" el prefijo con padding extra y offsets en bloques.

// Ejemplo ilustrativo para detectar la longitud del prefijo random (R) en el ejercicio 14.
// Problema: No sabemos len(R), así que no podemos calcular el padding exacto para alinear nuestro input (X) y el target (T).
// Situaciones posibles (block_size=4 para simplicidad; R variable, PT = R + X + T):
// - len(R)=1: R XXX | T TTT | T
// - len(R)=2: RR XX | XT TT | TT
// - len(R)=3: RRR X | XX TT | TTT
// - len(R)=4: RRRR | XXX T | TTTT
//
// Solución: Envía inputs X crecientes ('A's). Observa CT: Cuando añades 1 byte a X pero un bloque CT no cambia,
// ese bloque PT es solo R + X (sin T). Reduce X en 2 bloques para "reiniciar" alineación como en challenge 12.
// Ejemplo paso a paso:
// RRTT TT
// RRXT TTT
// RRXX TTTT
// RRXX XTTT T  PRIMER BLOQUE NO CAMBIA
// RRXX XXXT TTT     ESTAMOS EN EL EJER12

namespace
{
    const char *UNKNOWN_B64 =
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        "YnkK";

    std::vector<unsigned char> GLOBAL_KEY = generate_random_key();
    std::vector<unsigned char> UNKNOWN_BYTES = base64_to_bytes(UNKNOWN_B64);
    int PREFIX_LEN = 5 + rand() % 6;
    //int PREFIX_LEN = 5;
}

std::vector<unsigned char> ecb_oracle(const std::vector<unsigned char> &message)
{
    std::vector<unsigned char> full(PREFIX_LEN, 'P');
    full.insert(full.end(), message.begin(), message.end());
    full.insert(full.end(), UNKNOWN_BYTES.begin(), UNKNOWN_BYTES.end());
    return aes_ecb_encrypt(full, GLOBAL_KEY.data());
}

// Detecta la longitud exacta del prefijo aleatorio (constante entre llamadas).
// Idea: Envía probes de 'pad' + 2*block_size 'A's. Cuando dos bloques consecutivos de CT sean idénticos,
// esos corresponden a dos bloques PT de 'A's puros (tu control). Calcula prefix_len = posición del primer 'A' - pad.
// Prueba pads 0 a block_size-1 para forzar alineación.
int detect_prefix_length(int block_size) {
    // Probar todos los rellenos posibles de 0..block_size-1
    // para forzar que existan dos bloques idénticos consecutivos de datos controlados
    std::vector<unsigned char> ct;
    for (int pad = 0; pad < block_size; ++pad) {
        // Construimos: pad bytes no significativos + 2*block_size de 'A'
        std::vector<unsigned char> probe(pad + 2 * block_size, 'A');
        ct = ecb_oracle(probe);

        // Dividimos ciphertext en bloques y buscamos el primer par de bloques consecutivos iguales
        size_t nblocks = ct.size() / block_size;
        for (size_t b = 0; b + 1 < nblocks; ++b) {
            bool equal = true;
            for (int i = 0; i < block_size; ++i) {
                if (ct[b * block_size + i] != ct[(b + 1) * block_size + i]) {
                    equal = false;
                    break;
                }
            }
            if (equal) {
                // Si encontramos dos bloques iguales en posición b,b+1,
                // entonces esos bloques corresponden a bloques totalmente controlados por 'A'
                // El primer byte de ese bloque (en el plaintext completo) está en:
                // byte_index = b * block_size
                // Sabemos que antes de esos 'A' hay prefix_len + pad bytes.
                // Por tanto: prefix_len = b*block_size - pad
                int prefix_len = static_cast<int>(b * block_size) - pad;
                if (prefix_len < 0) prefix_len = 0; // guardia por seguridad
                return prefix_len;
            }
        }
    }
    // Si no lo encontramos, devolvemos -1 (error)
    return -1;
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

std::vector<unsigned char> decrypt_ecb_unknown_string(int block_size, int prefix_len = 0)
{
    // Caracteres que se van adivinando
    std::vector<unsigned char> known;
    size_t total_len = ecb_oracle({}).size();

    // Cuantas As meter para alinear el bloque de prefijo
    int offset_pad = block_size - (prefix_len % block_size);

    // Cuantos bloques nos tenemos que saltar para ignorar el prefijo
    int block_offset = (prefix_len + offset_pad) / block_size;

    for (size_t i = 0; i < total_len; ++i)
    {
        // Posicion del bloque que estamos descifrando
        size_t block_index = i / block_size;

        // Longitud del padding necesario para alinear el byte a adivinar al final de un bloque
        size_t pad_len = block_size - (i % block_size) - 1;

        std::vector<unsigned char> input(pad_len + offset_pad, 'A');
        auto reference = ecb_oracle(input);

        // Calcular todos los valores posibles de AAAAAAAx encriptados (256)
        std::map<std::vector<unsigned char>, unsigned char> dict;
        for (int b = 0; b < 256; ++b)
        {
            std::vector<unsigned char> trial = input;
            trial.insert(trial.end(), known.begin(), known.end());
            trial.push_back(static_cast<unsigned char>(b));

            auto encrypted = ecb_oracle(trial);
            std::vector<unsigned char> block(encrypted.begin() + block_index * block_size + block_offset * block_size,
                                             encrypted.begin() + (block_index + 1) * block_size + block_offset * block_size);
            dict[block] = static_cast<unsigned char>(b);
        }


        std::vector<unsigned char> target_block(reference.begin() + block_index * block_size + block_offset * block_size,
                                                reference.begin() + (block_index + 1) * block_size + block_offset * block_size);

        if (dict.count(target_block)) // Existe
        {
            known.push_back(dict[target_block]);
        }
        else
        {
            break;
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

    int prefix_len = detect_prefix_length(block_size);
    if (prefix_len < 0) {
        std::cerr << "No pude detectar prefix_len\n";
        return 1;
    }
    std::cout << "Prefix length detectado: " << prefix_len << "\n";

    auto decrypted = decrypt_ecb_unknown_string(block_size, prefix_len);
    std::string result(decrypted.begin(), decrypted.end());

    std::cout << "Mensaje descifrado:\n" << result << "\n";
    return 0;
}