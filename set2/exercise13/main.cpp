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
// Enunciado del ejercicio 13: ECB cut-and-paste

// Write a k=v parsing routine, as if for a structured cookie. The routine should take:

// foo=bar&baz=qux&zap=zazzle

// ... and produce:

// {
//   foo: 'bar',
//   baz: 'qux',
//   zap: 'zazzle'
// }

// (you know, the object; I don't care if you convert it to JSON).

// Now write a function that encodes a user profile in that format, given an email address. You should have something like:

// profile_for("foo@bar.com")

// ... and it should produce:

// {
//   email: 'foo@bar.com',
//   uid: 10,
//   role: 'user'
// }

// ... encoded as:

// email=foo@bar.com&uid=10&role=user

// Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

// Now, two more easy functions. Generate a random AES key, then:

//     Encrypt the encoded user profile under the key; "provide" that to the "attacker".
//     Decrypt the encoded user profile and parse it.

// Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.

//------------------------------------------------------------------------------------------------------------------

namespace
{
    std::vector<unsigned char> GLOBAL_KEY = generate_random_key();
}

std::map<std::string, std::string> parse_kv(const std::string &s)
{
    std::map<std::string, std::string> result;
    std::stringstream ss(s);
    std::string pair;

    while (std::getline(ss, pair, '&'))
    {
        size_t pos = pair.find('=');
        if (pos != std::string::npos)
        {
            std::string key = pair.substr(0, pos);
            std::string value = pair.substr(pos + 1);
            result[key] = value;
        }
    }
    return result;
}

std::string sanitize_email(const std::string &email)
{
    std::string clean;
    for (char c : email)
    {
        if (c != '&' && c != '=')
        {
            clean.push_back(c);
        }
    }
    return clean;
}

std::string profile_for(const std::string &email)
{
    std::string clean = sanitize_email(email);
    return "email=" + clean + "&uid=10&role=user";
}

std::vector<unsigned char> encrypt_profile(const std::string &profile)
{
    std::vector<unsigned char> data(profile.begin(), profile.end());
    return aes_ecb_encrypt(data, GLOBAL_KEY.data());
}

std::string decrypt_profile(const std::vector<unsigned char> &ciphertext)
{
    auto decrypted = aes_ecb_decrypt(ciphertext, GLOBAL_KEY.data());
    return std::string(decrypted.begin(), decrypted.end());
}

void print_blocks(const std::string &label, const std::string &plaintext)
{
    std::cout << label << " (" << plaintext.size() << " bytes):\n";
    for (size_t i = 0; i < plaintext.size(); i += 16)
    {
        std::string chunk = plaintext.substr(i, std::min<size_t>(16, plaintext.size() - i));
        std::cout << "[" << (i / 16) << "] " << chunk << "\n";
    }
    std::cout << "----\n";
}

int main()
{
    std::string victim_profile_plain = profile_for("alice12345678");
    print_blocks("Perfil víctima", victim_profile_plain);

    std::string crafted_email = std::string(10, 'A') + "admin" + std::string(11, '\x0b');
    std::string admin_profile_plain = profile_for(crafted_email);
    print_blocks("Perfil especial", admin_profile_plain);

    auto victim_cipher = encrypt_profile(victim_profile_plain);
    auto admin_cipher = encrypt_profile(admin_profile_plain);

    std::cout << "Perfil víctima descifrado:\n"
              << decrypt_profile(victim_cipher) << "\n";
    std::cout << "Perfil especial descifrado:\n"
              << decrypt_profile(admin_cipher) << "\n";

    std::vector<unsigned char> forged_cipher = victim_cipher;
    for (size_t i = 0; i < 16; ++i)
    {
        forged_cipher[32 + i] = admin_cipher[16 + i];
    }

    std::string forged_profile_plain = decrypt_profile(forged_cipher);
    std::cout << "Perfil forjado descifrado:\n"
              << forged_profile_plain << "\n";

    auto parsed = parse_kv(forged_profile_plain);
    std::cout << "Rol final = " << parsed["role"] << "\n";

    return 0;
}