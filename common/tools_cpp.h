#pragma once

#include <string>
#include <vector>
#include <set>
#include <cctype>
#include <stdexcept>
#include <array>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

inline const std::array<int8_t, 256> base64_decode_table()
{

    std::array<int8_t, 256> t{};
    t.fill(-1);

    for (int i = 'A'; i <= 'Z'; ++i)
        t[i] = i - 'A';
    for (int i = 'a'; i <= 'z'; ++i)
        t[i] = i - 'a' + 26;
    for (int i = '0'; i <= '9'; ++i)
        t[i] = i - '0' + 52;
    t[static_cast<unsigned char>('+')] = 62;
    t[static_cast<unsigned char>('/')] = 63;
    t[static_cast<unsigned char>('=')] = -2;

    return t;
}

inline std::vector<unsigned char> base64_to_bytes(const std::string &input)
{
    const auto &DECODE = base64_decode_table();

    std::vector<unsigned char> out;
    out.reserve((input.size() * 3) / 4);

    uint32_t acc = 0;
    int acc_bits = 0;
    bool seen_pad = false;

    for (unsigned char c : input)
    {
        if (std::isspace(c))
            continue;

        int8_t v = DECODE[c];

        if (v == -1)
            continue;

        if (v == -2)
        {
            seen_pad = true;
            continue;
        }

        if (seen_pad)
            break;

        acc = (acc << 6) | static_cast<uint32_t>(v);
        acc_bits += 6;

        while (acc_bits >= 8)
        {
            acc_bits -= 8;
            unsigned char byte = static_cast<unsigned char>((acc >> acc_bits) & 0xFFu);
            out.push_back(byte);
            acc &= ((1u << acc_bits) - 1u);
        }
    }

    return out;
}

std::vector<unsigned char> xor_repeating(const std::vector<unsigned char> &data,
                                         const std::vector<unsigned char> &key)
{
    if (key.empty())
    {
        throw std::invalid_argument("Key must not be empty");
    }
    std::vector<unsigned char> result(data.size());
    for (size_t i = 0; i < data.size(); ++i)
    {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

std::vector<unsigned char> xor_key_cpp(const std::vector<unsigned char> &left, const std::vector<unsigned char> &right)
{

    if (left.size() != right.size())
    {
        throw std::invalid_argument("Vectors must be of the same size for XOR operation.");
    }

    std::vector<unsigned char> result(left.size());
    for (int i = 0; i < 16; ++i)
        result[i] = left[i] ^ right[i];
    return result;
}

unsigned char solve_single_byte_xor(const std::vector<unsigned char> &column)
{
    int best_score = -1;
    unsigned char best_key = 0;

    for (int k = 0; k < 256; k++)
    {
        std::vector<unsigned char> response(column.size());
        for (size_t i = 0; i < column.size(); i++)
        {
            response[i] = column[i] ^ static_cast<unsigned char>(k);
        }

        int score = getScore(response.data(), response.size());

        if (score > best_score)
        {
            best_score = score;
            best_key = static_cast<unsigned char>(k);
        }
    }
    return best_key;
}

std::vector<unsigned char> pkcs7_pad(const std::vector<unsigned char> &input, size_t block_size)
{
    size_t pad_len = block_size - (input.size() % block_size);
    if (pad_len == 0)
    {
        pad_len = block_size;
    }

    std::vector<unsigned char> padded = input;
    padded.insert(padded.end(), pad_len, static_cast<unsigned char>(pad_len));
    return padded;
}

std::vector<unsigned char> pkcs7_unpad(const std::vector<unsigned char> &input, size_t block_size = 16)
{
    if (input.empty() || input.size() % block_size != 0)
    {
        throw std::runtime_error("Invalid size: not a multiple of block size");
    }

    unsigned char pad_len = input.back();

    if (pad_len == 0 || pad_len > block_size)
    {
        throw std::runtime_error("Invalid padding: value out of range");
    }

    for (size_t i = 0; i < pad_len; i++)
    {
        if (input[input.size() - 1 - i] != pad_len)
        {
            throw std::runtime_error("Invalid padding: inconsistent bytes");
        }
    }

    return std::vector<unsigned char>(input.begin(), input.end() - pad_len);
}

std::vector<unsigned char> aes_ecb_encrypt(const std::vector<unsigned char> &plaintext, const unsigned char *key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 1);

    std::vector<unsigned char> ciphertext(plaintext.size() + 16);
    int len, ciphertext_len;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::vector<unsigned char> aes_ecb_encrypt_block(const std::vector<unsigned char> &block, const unsigned char *key)
{
    std::vector<unsigned char> out(16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int len;
    EVP_EncryptUpdate(ctx, out.data(), &len, block.data(), 16);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::vector<unsigned char> aes_ecb_decrypt(const std::vector<unsigned char> &ciphertext, const unsigned char *key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 1);

    std::vector<unsigned char> plaintext(ciphertext.size() + 16);
    int len, plaintext_len;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    return plaintext;
}

std::vector<unsigned char> aes_ecb_decrypt_block(const std::vector<unsigned char> &block, const unsigned char *key)
{
    std::vector<unsigned char> out(16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    int len;
    EVP_DecryptUpdate(ctx, out.data(), &len, block.data(), 16);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::vector<unsigned char> aes_cbc_encrypt(const std::vector<unsigned char> &plaintext, const unsigned char *key, const std::vector<unsigned char> &iv)
{
    std::vector<unsigned char> padded = pkcs7_pad(plaintext, 16);
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> prev_block = iv;

    for (size_t i = 0; i < padded.size(); i += 16)
    {
        std::vector<unsigned char> block(padded.begin() + i, padded.begin() + i + 16);
        auto xored = xor_key_cpp(block, prev_block);
        auto encrypted = aes_ecb_encrypt_block(xored, key);
        ciphertext.insert(ciphertext.end(), encrypted.begin(), encrypted.end());
        prev_block = encrypted;
    }

    return ciphertext;
}

std::vector<unsigned char> aes_cbc_decrypt(const std::vector<unsigned char> &ciphertext, const unsigned char *key, const std::vector<unsigned char> &iv)
{
    std::vector<unsigned char> plaintext;
    std::vector<unsigned char> prev_block = iv;

    for (size_t i = 0; i < ciphertext.size(); i += 16)
    {
        std::vector<unsigned char> block(ciphertext.begin() + i, ciphertext.begin() + i + 16);
        auto decrypted = aes_ecb_decrypt_block(block, key);
        auto xored = xor_key_cpp(decrypted, prev_block);
        plaintext.insert(plaintext.end(), xored.begin(), xored.end());
        prev_block = block;
    }
    std::vector<unsigned char> unpadded_plaintext = pkcs7_unpad(plaintext);
    return unpadded_plaintext;
}

std::vector<unsigned char> generate_random_key()
{
    std::vector<unsigned char> key(16);
    RAND_bytes(key.data(), 16);
    return key;
}

std::vector<unsigned char> random_pad_input(const std::vector<unsigned char> &input)
{
    int prefix_len = 5 + rand() % 6;
    int suffix_len = 5 + rand() % 6;

    std::vector<unsigned char> padded(prefix_len + input.size() + suffix_len);
    RAND_bytes(padded.data(), prefix_len);
    std::copy(input.begin(), input.end(), padded.begin() + prefix_len);
    RAND_bytes(padded.data() + prefix_len + input.size(), suffix_len);

    return padded;
}

std::vector<unsigned char> encryption_oracle(const std::vector<unsigned char> &input)
{
    std::vector<unsigned char> key = generate_random_key();
    std::vector<unsigned char> padded_input = random_pad_input(input);
    std::vector<unsigned char> iv(16);
    RAND_bytes(iv.data(), 16);

    if (rand() % 2 == 0)
    {
        return aes_ecb_encrypt(padded_input, key.data());
    }
    else
    {
        return aes_cbc_encrypt(padded_input, key.data(), iv);
    }
}

std::string detect_mode(const std::vector<unsigned char> &ciphertext)
{
    std::set<std::vector<unsigned char>> blocks;

    for (size_t i = 0; i < ciphertext.size(); i += 16)
    {
        std::vector<unsigned char> block(ciphertext.begin() + i, ciphertext.begin() + i + 16);
        if (blocks.count(block))
        {
            return "ECB";
        }
        blocks.insert(block);
    }

    return "CBC";
}
