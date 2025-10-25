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

int bit_counter(char b)
{
    char count = 0;
    for (int bitIndex = 0; bitIndex < (sizeof(char) * 8) - 1; ++bitIndex)
    {
        if (b & 0x01)
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
    for (size_t i = 0; i < a.size(); ++i)
    {
        dist += bit_counter(static_cast<unsigned char>(a[i] ^ b[i]));
    }
    return dist;
}

std::vector<int> guess_keysizes(const std::vector<unsigned char> &ct,
                                int min_k = 2, int max_k = 40, int top_n = 3)
{
    struct Candidate
    {
        int keysize;
        double score;
    };
    std::vector<Candidate> scores;

    for (int k = min_k; k <= max_k; ++k)
    {
        if (ct.size() < static_cast<size_t>(k * 4))
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

    std::sort(scores.begin(), scores.end(),
              [](const Candidate &a, const Candidate &b)
              { return a.score < b.score; });

    std::vector<int> result;
    for (int i = 0; i < top_n && i < (int)scores.size(); ++i)
    {
        result.push_back(scores[i].keysize);
    }
    return result;
}

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
        auto cols = transpose_blocks(ciphertext, keysize);

        std::vector<unsigned char> key;
        for (const auto &col : cols)
        {
            unsigned char k = solve_single_byte_xor(col);
            key.push_back(k);
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