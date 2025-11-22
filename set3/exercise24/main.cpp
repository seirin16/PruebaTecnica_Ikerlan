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
#include <cstdint>
#include <optional>
#include <chrono>
#include <random>

#include "tools.h"
#include "tools_cpp.h"

//-----------------------------------------------------------------------------------------------------------------
// Enunciado del ejercicio 24: Create the MT19937 stream cipher and break it

// You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.

// Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.

// Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.

// From the ciphertext, recover the "key" (the 16 bit seed).

// Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.

// Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.

//------------------------------------------------------------------------------------------------------------------

// Lo que estamos haciendo aquí es bastante curioso: estamos usando el Mersenne Twister (MT19937),
// que normalmente sirve para generar números pseudoaleatorios, como si fuera un cifrador de flujo.

// La idea es simple: el generador produce números de 32 bits, los partimos en bytes y los usamos
// como un "keystream". Luego, para cifrar un mensaje, hacemos XOR entre cada byte del texto y cada
// byte del keystream. Si aplicamos el mismo proceso otra vez con la misma clave, recuperamos el
// mensaje original. Es decir, cifrado y descifrado son exactamente el mismo procedimiento.

// Dónde está la trampa? La clave que usamos para inicializar MT19937 es solo de 16 bits.
// Eso significa que hay como mucho 65.536 posibles claves. Para un atacante, probarlas todas es
// cuestión de segundos. En el ejercicio, ciframos un texto que termina con 14 letras 'A'. Como el
// atacante sabe que al final deberían aparecer esas 'A', puede recorrer todas las claves posibles
// y comprobar cuál produce ese patrón. En cuanto encuentra la coincidencia, ya tiene la clave real.

// La segunda parte del reto es aún más ilustrativa: generamos un "token de reseteo de contraseña"
// usando MT19937 sembrado con el tiempo actual. Como el tiempo es predecible y además reducimos la
// semilla a 16 bits, el token también se puede romper fácilmente probando todas las semillas posibles.

// En resumen: MT19937 es un buen generador para simulaciones estadísticas, pero no es seguro para
// criptografía. Si la semilla es pequeña o predecible, la seguridad es una mierda


class MT19937_32
{
public:
    static constexpr int n = 624, m = 397;
    static constexpr uint32_t a = 0x9908B0DF;
    static constexpr uint32_t u = 11, d = 0xFFFFFFFF;
    static constexpr uint32_t s = 7, b = 0x9D2C5680;
    static constexpr uint32_t t = 15, c = 0xEFC60000;
    static constexpr uint32_t l = 18;
    static constexpr uint32_t f = 1812433253;

    explicit MT19937_32(uint32_t seed) : state(n), index(n)
    {
        state[0] = seed;
        for (int i = 1; i < n; ++i)
            state[i] = f * (state[i - 1] ^ (state[i - 1] >> 30)) + static_cast<uint32_t>(i);
    }

    uint32_t next_u32()
    {
        if (index >= n)
            twist();
        uint32_t y = state[index++];
        y ^= (y >> u) & d;
        y ^= (y << s) & b;
        y ^= (y << t) & c;
        y ^= (y >> l);
        return y;
    }

private:
    std::vector<uint32_t> state;
    int index;

    void twist()
    {
        static constexpr uint32_t UPPER_MASK = 0x80000000u;
        static constexpr uint32_t LOWER_MASK = 0x7FFFFFFFu;
        for (int i = 0; i < n; ++i)
        {
            uint32_t x = (state[i] & UPPER_MASK) | (state[(i + 1) % n] & LOWER_MASK);
            uint32_t xA = x >> 1;
            if (x & 1U)
                xA ^= a;
            state[i] = state[(i + m) % n] ^ xA;
        }
        index = 0;
    }
};

// Genera bytes de keystream a partir de MT19937 (dividiendo cada u32 en 4 bytes big-endian).
static std::vector<uint8_t> mt19937_keystream(uint32_t seed, size_t length_bytes)
{
    MT19937_32 prng(seed);
    std::vector<uint8_t> ks;
    ks.reserve(length_bytes);
    while (ks.size() < length_bytes)
    {
        uint32_t r = prng.next_u32();
        ks.push_back(static_cast<uint8_t>((r >> 24) & 0xFF));
        ks.push_back(static_cast<uint8_t>((r >> 16) & 0xFF));
        ks.push_back(static_cast<uint8_t>((r >> 8) & 0xFF));
        ks.push_back(static_cast<uint8_t>(r & 0xFF));
    }
    ks.resize(length_bytes);
    return ks;
}

// XOR byte a byte entre mensaje y keystream
static std::vector<uint8_t> transform_mt19937(const std::vector<uint8_t> &msg, uint16_t key16)
{
    uint32_t seed = static_cast<uint32_t>(key16);
    auto ks = mt19937_keystream(seed, msg.size());
    std::vector<uint8_t> out(msg.size());
    for (size_t i = 0; i < msg.size(); ++i)
        out[i] = msg[i] ^ ks[i];
    return out;
}
// Convierte un vector de bytes a una representación hexadecimal en string
static std::string to_hex(const std::vector<uint8_t> &v)
{
    static const char *hex = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (auto b : v)
    {
        s.push_back(hex[(b >> 4) & 0xF]);
        s.push_back(hex[b & 0xF]);
    }
    return s;
}

// Dado un ciphertext de (prefijo aleatorio + 14 'A'), fuerza bruta la clave probando si el
// descifrado termina en "AAAAAAAAAAAAAA".
static std::optional<uint16_t> recover_key_from_ciphertext_suffix_A(const std::vector<uint8_t> &ctxt)
{
    const std::string suffix(14, 'A');
    for (uint32_t key = 0; key <= 0xFFFF; ++key)
    {
        auto pt = transform_mt19937(ctxt, static_cast<uint16_t>(key));
        if (pt.size() >= suffix.size())
        {
            bool match = true;
            for (size_t i = 0; i < suffix.size(); ++i)
            {
                if (pt[pt.size() - suffix.size() + i] != static_cast<uint8_t>(suffix[i]))
                {
                    match = false;
                    break;
                }
            }
            if (match)
                return static_cast<uint16_t>(key);
        }
    }
    return std::nullopt;
}

// Genera un token de 16 bytes con MT19937 sembrado con el timestamp actual, reducido a 16 bits.
static std::vector<uint8_t> gen_token_time_seed_16bit()
{
    using clock = std::chrono::system_clock;
    uint64_t now = std::chrono::time_point_cast<std::chrono::seconds>(clock::now())
                       .time_since_epoch()
                       .count();
    uint16_t seed16 = static_cast<uint16_t>(now & 0xFFFFu);
    auto ks = mt19937_keystream(seed16, 16);
    return ks;
}

// Verifica si un token podría ser generado por MT19937 con alguna semilla 16-bit.
// Nota: fuerza bruta sobre 65.536 semillas. Para un chequeo más realista, recorrer una ventana temporal cercana.
static bool is_generated_with_mt19937_16bit_seed(const std::vector<uint8_t> &token)
{
    for (uint32_t seed = 0; seed <= 0xFFFF; ++seed)
    {
        auto ks = mt19937_keystream(seed, token.size());
        if (ks == token)
            return true;
    }
    return false;
}

int main()
{

    // Demostración de cifrado/descifrado
    {
        const std::string msg = "hello there!";
        uint16_t key = 1234;
        std::vector<uint8_t> pt(msg.begin(), msg.end());
        auto ct = transform_mt19937(pt, key);
        auto dec = transform_mt19937(ct, key);

        std::cout << "[Demo] Cifrado/descifrado\n";
        std::cout << "PT:  " << msg << "\n";
        std::cout << "CT:  " << to_hex(ct) << "\n";
        std::cout << "DEC: " << std::string(dec.begin(), dec.end()) << "\n\n";
    }

    // Romper la clave 16-bit usando sufijo conocido de 14 'A'
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> keydist(0, 0xFFFF);
        std::uniform_int_distribution<int> prefLenDist(2, 20);
        std::uniform_int_distribution<int> byteDist(0, 255);

        uint16_t key = static_cast<uint16_t>(keydist(gen));
        int prefix_len = prefLenDist(gen);

        std::vector<uint8_t> prefix(prefix_len);
        for (int i = 0; i < prefix_len; ++i)
            prefix[i] = static_cast<uint8_t>(byteDist(gen));

        std::string known(14, 'A');
        std::vector<uint8_t> pt = prefix;
        pt.insert(pt.end(), known.begin(), known.end());

        auto ct = transform_mt19937(pt, key);
        auto recovered = recover_key_from_ciphertext_suffix_A(ct);

        std::cout << "[Break] Clave real: " << key << "\n";
        if (recovered)
        {
            std::cout << "[Break] Clave recuperada: " << *recovered
                      << (key == *recovered ? " (OK)\n\n" : " (MISMATCH)\n\n");
        }
        else
        {
            std::cout << "[Break] No se pudo recuperar la clave.\n\n";
        }
    }

    // Token basado en tiempo y verificación
    {
        auto token = gen_token_time_seed_16bit();
        bool looks_mt = is_generated_with_mt19937_16bit_seed(token);

        std::cout << "[Token] Generado (hex): " << to_hex(token) << "\n";
        std::cout << "[Token] ¿Coincide con alguna semilla 16-bit de MT19937? "
                  << (looks_mt ? "Sí" : "No") << "\n";
    }

    return 0;
}
