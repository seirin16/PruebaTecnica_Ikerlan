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
// Enunciado del ejercicio 6: Break repeating-key XOR

// It is officially on, now.

// This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.

// There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

// Decrypt it.

// Here's how:

//     Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
//     Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:

//     this is a test

//     and

//     wokka wokka!!!

//     is 37. Make sure your code agrees before you proceed.
//     For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
//     The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
//     Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
//     Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
//     Solve each block as if it was single-character XOR. You already have code to do this.
//     For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

// This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
// No, that's not a mistake.

// We get more tech support questions for this challenge than any of the other ones. We promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.

//------------------------------------------------------------------------------------------------------------------

//Este ejercicio ya es algo más complejo. Aqui si hay que romper un cifrado de XOR con clave repetida,
//usando para ello la distancia de Hamming para adivinar la longitud de la clave

//La distancia de Hamming es el numero de bits que difieren entre dos bloques de igual longitud. Por ejemplo,
//la distancia de Hamming entre "this is a test" y "wokka wokka!!!" es 37. Este 37 significa que tienen una estructura similar,
//si además tuvieran más caracrteres iguales, la distancia de Hamming sería menor. (- distancia = más parecido)

//Lo que te puedes preguntar es pq funciona esto de hamming para adivinar la longitud de la clave. La razon es que si tomas dos bloques
//de texto cifrado con la misma clave, y haces un XOR entre ambos bloques. La distancia de Hamming mide cuántos bits 
//difieren (es decir, cuántos 1s hay en el resultado del XOR entre dos bloques). Cuanto menor sea ese número, 
//significa que más bits son iguales. Eso implica mayor similitud entre los dos bloques después del XOR.

int bit_counter(char b)
{
    char count = 0;
    for (int bitIndex = 0; bitIndex < (sizeof(char) * 8) - 1; ++bitIndex) //Para cada bit del byte
    {
        if (b & 0x01) //Si el bit menos significativo es 1
        {
            count++;
        }
        b = b >> 1;
    }
    return count;
}

size_t hamming_distance_bits(const std::vector<unsigned char> &a,
                             const std::vector<unsigned char> &b)
{
    if (a.size() != b.size())
    {
        throw std::invalid_argument("Hamming requires equal-length buffers");
    }
    size_t dist = 0;
    for (size_t i = 0; i < a.size(); ++i) //Para cada byte
    {
        dist += bit_counter(static_cast<unsigned char>(a[i] ^ b[i])); //Cuenta los bits a 1 del XOR entre ambos bytes
    }
    return dist;
}

//Funcion que devuelve los posibles tamaños de clave, ordenados por probabilidad (menor distancia de Hamming normalizada)
//Usamos la media de las distancias de Hamming normalizadas entre los primeros 4 bloques de tamaño k para mas precisión
//top_n indica cuantos tamaños de clave devolver que eso es lo que vamos a probar luego
std::vector<int> guess_keysizes(const std::vector<unsigned char> &ct,
                                int min_k = 2, int max_k = 40, int top_n = 3)
{
    struct Candidate
    {
        int keysize;
        double score;
    };
    std::vector<Candidate> scores;

    for (int k = min_k; k <= max_k; ++k) //Para cada posible tamaño de clave (2 a 40)
    {
        if (ct.size() < static_cast<size_t>(k * 4)) //Necesitamos al menos 4 bloques de tamaño k para hacer la media
            continue;

        auto b1 = std::vector<unsigned char>(ct.begin(), ct.begin() + k);
        auto b2 = std::vector<unsigned char>(ct.begin() + k, ct.begin() + 2 * k);
        auto b3 = std::vector<unsigned char>(ct.begin() + 2 * k, ct.begin() + 3 * k);
        auto b4 = std::vector<unsigned char>(ct.begin() + 3 * k, ct.begin() + 4 * k);

        double d12 = (double)hamming_distance_bits(b1, b2) / k;
        double d34 = (double)hamming_distance_bits(b3, b4) / k;
        double d13 = (double)hamming_distance_bits(b1, b3) / k;
        double d24 = (double)hamming_distance_bits(b2, b4) / k;

        double avg = (d12 + d34 + d13 + d24) / 4.0;

        scores.push_back({k, avg});
    }

    //Ordenamos los tamaños de clave por puntuacion (distancia de Hamming normalizada). Cuanto menor, mejor
    std::sort(scores.begin(), scores.end(),
              [](const Candidate &a, const Candidate &b)
              { return a.score < b.score; }); 

    std::vector<int> result;
    for (int i = 0; i < top_n && i < (int)scores.size(); ++i) 
    {
        result.push_back(scores[i].keysize); //Devolvemos los top_n tamaños de clave más probables. No quieres probar todos los 39 posibles (2-40), porque sería ineficiente y ruidoso (algunos KEYSIZE falsos podrían colarse por azar). En cambio, tomas los 2-3 más prometedores (los con la distancia más baja) para atacar después.
    }
    return result;
}

//Funcion que transpone los bloques de tamaño keysize
//Esto sirve para agrupar los bytes que han sido cifrados con la misma byte de la clave
std::vector<std::vector<unsigned char>>
transpose_blocks(const std::vector<unsigned char> &ct, int keysize)
{
    size_t blocks = ct.size() / keysize;
    std::vector<std::vector<unsigned char>> cols(keysize);
    for (int i = 0; i < keysize; ++i)
    {
        cols[i].reserve(blocks);
        for (size_t b = 0; b < blocks; ++b)
        {
            cols[i].push_back(ct[b * keysize + i]);
        }
    }
    return cols;
}

int main()
{
    std::ifstream file("/home/seirin16/pruebaIkerlan/PruebaTecnica_Ikerlan/set1/exercise6/file_exercise6.txt");
    std::stringstream ss;
    ss << file.rdbuf();
    std::string base64_data = ss.str();

    std::vector<unsigned char> ciphertext = base64_to_bytes(base64_data);

    std::string str1 = "this is a test";
    std::string str2 = "wokka wokka!!!";

    std::vector<unsigned char> vec1(str1.begin(), str1.end());
    std::vector<unsigned char> vec2(str2.begin(), str2.end());
    size_t distance = hamming_distance_bits(vec1, vec2);
    std::cout << "Hamming distance between \"" << str1 << "\" and \"" << str2 << "\": " << distance << std::endl;

    std::vector<int> ks_candidates = guess_keysizes(ciphertext, 2, 40, 3);

    std::vector<unsigned char> best_plain;
    std::vector<unsigned char> best_key;
    int best_score = 0;

    for (int keysize : ks_candidates)
    {
        //Transponemos los bloques pq asi agrupamos los bytes cifrados con la misma byte de la clave
        auto cols = transpose_blocks(ciphertext, keysize); 
        std::vector<unsigned char> key;
        for (const auto &col : cols)
        {
            unsigned char k = solve_single_byte_xor(col); //Resolvemos cada bloque como si fuera un cifrado XOR con byte unico
            key.push_back(k); //Obtenemos la clave completa
        }

        auto plain = xor_repeating(ciphertext, key);

        int score = getScore(plain.data(), plain.size());
        if (score > best_score)
        {
            best_score = score;
            best_plain = std::move(plain);
            best_key = std::move(key);
        }
    }

    std::string key_str(best_key.begin(), best_key.end());
    std::string plain_str(best_plain.begin(), best_plain.end());

    std::cout << "Clave estimada: " << key_str << "\n";
    std::cout << "Texto plano:\n"
              << plain_str << "\n";

    return 0;
}