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

#include "tools.h"
#include "tools_cpp.h"

//-----------------------------------------------------------------------------------------------------------------
// Enunciado del ejercicio 21: Implement the MT19937 Mersenne Twister RNG

// You can get the psuedocode for this from Wikipedia.

// If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you MT19937 as "rand()"; don't use rand(). Write the RNG yourself.

//------------------------------------------------------------------------------------------------------------------

// MT19937 mantiene un estado de 624 enteros de 32 bits.
// Inicializamos el estado con la semilla y una fórmula recursiva.
// Cada vez que pedimos un número:
//   1. Combinamos varios valores del estado para crear un nuevo x.
//   2. Aplicamos tempering a x para obtener la salida.
//   3. Insertamos x al final del estado y descartamos el primero.
// Así conseguimos una secuencia muy larga (periodo 2^19937-1) y bien distribuida.

class MT19937_32
{
public:
    // Parámetros del algoritmo
    static constexpr int w = 32;
    static constexpr int n = 624;
    static constexpr int m = 397;
    static constexpr int r = 31;
    static constexpr uint32_t a = 0x9908B0DF;
    static constexpr uint32_t u = 11;
    static constexpr uint32_t d = 0xFFFFFFFF;
    static constexpr uint32_t s = 7;
    static constexpr uint32_t b = 0x9D2C5680;
    static constexpr uint32_t t = 15;
    static constexpr uint32_t c = 0xEFC60000;
    static constexpr uint32_t l = 18;
    static constexpr uint32_t f = 1812433253;

    static constexpr uint32_t UPPER_MASK = 0x80000000u; // bit más alto
    static constexpr uint32_t LOWER_MASK = 0x7FFFFFFFu; // 31 bits bajos

    // Máscaras
    static constexpr uint32_t high_mask = UPPER_MASK;
    static constexpr uint32_t low_mask = LOWER_MASK;

    MT19937_32(uint32_t seed = 5489)
    {
        state.resize(n);
        state[0] = seed;
        for (int i = 1; i < n; i++)
        {
            uint32_t prev = state[i - 1];
            state[i] = f * (prev ^ (prev >> (w - 2))) + i;
            state[i] &= d; // mantener 32 bits
        }
        index = 0;
    }

    uint32_t next()
    {
        if (index == 0)
        {
            // regenerar estado
            for (int i = 0; i < n; i++)
            {
                uint32_t x = (state[i] & high_mask) + (state[(i + 1) % n] & low_mask);
                uint32_t xA = (x >> 1);
                if (x & 1u)
                    xA ^= a;
                state[i] = state[(i + m) % n] ^ xA;
            }
        }

        uint32_t y = state[index];
        // Tempering
        y ^= (y >> u) & d;
        y ^= (y << s) & b;
        y ^= (y << t) & c;
        y ^= (y >> l);

        index = (index + 1) % n;
        return y;
    }

private:
    std::vector<uint32_t> state;
    int index;
};

int main()
{
    MT19937_32 rng(5489); 

    for (int i = 0; i < 10; i++)
    {
        std::cout << rng.next() << "\n";
    }
    return 0;
}