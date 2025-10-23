#pragma once

#include <string>
#include <vector>
#include <cctype>
#include <stdexcept>
#include <array>
#include <cstdint>

inline const std::array<int8_t, 256>& base64_decode_table() {
    static const std::array<int8_t, 256> table = [] {
        std::array<int8_t, 256> t{};
        t.fill(-1);

        for (int i = 'A'; i <= 'Z'; ++i) t[i] = i - 'A';
        for (int i = 'a'; i <= 'z'; ++i) t[i] = i - 'a' + 26;
        for (int i = '0'; i <= '9'; ++i) t[i] = i - '0' + 52;
        t[static_cast<unsigned char>('+')] = 62;
        t[static_cast<unsigned char>('/')] = 63;
        t[static_cast<unsigned char>('=')] = -2;

        return t;
    }();
    return table;
}

inline std::vector<unsigned char> base64_to_bytes(const std::string &input)
{
    const auto& DECODE = base64_decode_table();

    // Reservamos: Base64 produce ~3 bytes por cada 4 chars
    std::vector<unsigned char> out;
    out.reserve((input.size() * 3) / 4);

    // Acumulador de bits: vamos sumando grupos de 6 bits
    uint32_t acc = 0;
    int acc_bits = 0;
    bool seen_pad = false; // hemos visto '='

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
