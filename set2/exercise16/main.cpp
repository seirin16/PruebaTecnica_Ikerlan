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
// Enunciado del ejercicio 16: CBC bitflipping attacks

// Generate a random AES key.

// Combine your padding code and CBC code to write two functions.

// The first function should take an arbitrary input string, prepend the string:

// "comment1=cooking%20MCs;userdata="

// .. and append the string:

// ";comment2=%20like%20a%20pound%20of%20bacon"

// The function should quote out the ";" and "=" characters.

// The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

// The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

// Return true or false based on whether the string exists.

// If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

// Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

// You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

//     Completely scrambles the block the error occurs in
//     Produces the identical 1-bit error(/edit) in the next ciphertext block.

// Stop and think for a second.

// Before you implement this attack, answer this question: why does CBC mode have this property?

//------------------------------------------------------------------------------------------------------------------

namespace
{
    std::vector<unsigned char> GLOBAL_AES_KEY = generate_random_key();
}

std::string sanitize_userdata(const std::string &s)
{
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s)
    {
        if (c == ';')
        {
            out += "%3B";
        }
        else if (c == '=')
        {
            out += "%3D";
        }
        else
        {
            out.push_back(c);
        }
    }
    return out;
}

std::vector<unsigned char> encrypt_userdata_cbc(const std::string &userdata, std::vector<unsigned char> &out_iv)
{
    const std::string prefix = "comment1=cooking%20MCs;userdata=";
    const std::string suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

    std::string clean = sanitize_userdata(userdata);

    std::string full = prefix + clean + suffix;
    std::vector<unsigned char> plain(full.begin(), full.end());

    auto padded = pkcs7_pad(plain, 16);

    out_iv.resize(16);
    RAND_bytes(out_iv.data(), 16);

    return aes_cbc_encrypt(padded, GLOBAL_AES_KEY.data(), out_iv);
}

bool is_admin(const std::vector<unsigned char> &ciphertext, const std::vector<unsigned char> &iv)
{
    std::vector<unsigned char> plain = aes_cbc_decrypt(ciphertext, GLOBAL_AES_KEY.data(), iv);
    std::cout << "Decrypted plaintext: " << std::string(plain.begin(), plain.end()) << std::endl;

    std::string s(plain.begin(), plain.end());

    if (s.find(";admin=true;") != std::string::npos)
    {
        return true;
    }

    return false;
}

void flip_ciphertext_for_admin(std::vector<unsigned char> &ciphertext, size_t target_block_index,
                               const std::vector<unsigned char> &placeholder, const std::vector<unsigned char> &desired)
{

    if (target_block_index == 0)
    {
        throw std::invalid_argument("Cannot flip to affect first plaintext block using previous block; flip IV instead.");
    }

    size_t block_size = 16;
    size_t prev_start = (target_block_index - 1) * block_size;
    if (placeholder.size() != desired.size())
    {
        throw std::invalid_argument("Placeholder and desired must have same length");
    }

    for (size_t i = 0; i < placeholder.size(); ++i)
    {
        unsigned char delta = placeholder[i] ^ desired[i];
        ciphertext[prev_start + i] ^= delta;
    }
}

int main()
{
    std::string placeholder_str = "AAAAAAAAAAAA";
    std::string desired_str = ";admin=true;";
    const std::string prefix = "comment1=cooking%20MCs;userdata=";
    size_t prefix_len = prefix.size();

    size_t block_size = 16;
    std::vector<unsigned char> iv;
    std::vector<unsigned char> ct;
    size_t target_block_index = 0;
    size_t trial_pad = 0;

    // Calculamos el block size. "Sabemos" que es 16, pero lo hacemos por si acaso.
    for (size_t pad = 0; pad < block_size; ++pad)
    {
        std::string trial_user(pad, 'A');
        trial_user += placeholder_str;
        ct = encrypt_userdata_cbc(trial_user, iv);
        if ((prefix_len + pad) % block_size == 0)
        {
            trial_pad = pad;
            target_block_index = (prefix_len + pad) / block_size;
            break;
        }
    }

    std::string userdata = std::string(trial_pad, 'A') + placeholder_str;
    ct = encrypt_userdata_cbc(userdata, iv);

    std::vector<unsigned char> placeholder(placeholder_str.begin(), placeholder_str.end());
    std::vector<unsigned char> desired(desired_str.begin(), desired_str.end());
    flip_ciphertext_for_admin(ct, target_block_index, placeholder, desired);

    bool ok = is_admin(ct, iv);
    std::cout << (ok ? "Admin granted\n" : "Admin not present\n");


    return 0;
}
