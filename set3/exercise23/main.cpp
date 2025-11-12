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
// Enunciado del ejercicio 23: Clone an MT19937 RNG from its output

// The internal state of MT19937 consists of 624 32 bit integers.

// For each batch of 624 outputs, MT permutes that internal state. By permuting state regularly, MT19937 achieves a period of 2**19937, which is Big.

// Each time MT19937 is tapped, an element of its internal state is subjected to a tempering function that diffuses bits through the result.

// The tempering function is invertible; you can write an "untemper" function that takes an MT19937 output and transforms it back into the corresponding element of the MT19937 state array.

// To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse order. There are two kinds of operations in the temper transform each applied twice; one is an XOR against a right-shifted value, and the other is an XOR against a left-shifted value AND'd with a magic number. So you'll need code to invert the "right" and the "left" operation.

// Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, untemper each of them to recreate the state of the generator, and splice that state into a new instance of the MT19937 generator.

// The new "spliced" generator should predict the values of the original.
// Stop and think for a second.
// How would you modify MT19937 to make this attack hard? What would happen if you subjected each tempered output to a cryptographic hash?

//------------------------------------------------------------------------------------------------------------------

// Cada vez que le pides un número, no te da directamente lo que tiene en su estado, sino que le aplica una especie de “maquillaje” llamado tempering.
// Ese tempering son unas cuantas operaciones de bits (XORs y desplazamientos) que sirven para que los números parezcan más aleatorios y estén mejor distribuidos.

// El detalle curioso es que ese tempering no destruye información, es totalmente reversible. Si capturas un número de salida y aplicas las operaciones inversas,
// puedes recuperar el valor original del estado que lo generó. Y si consigues 624 salidas consecutivas, puedes reconstruir el estado entero del generador.
// Con ese estado clonado, puedes crear tu propio MT19937 y a partir de ahí predecir exactamente los mismos números que iba a dar el original. Es como si hubieras
// copiado su cerebro.

//  MT19937 está muy bien para simulaciones, juegos o estadísticas, pero no es seguro para criptografía. Si alguien puede ver suficientes salidas,
// puede clonar el generador y adelantarse a todo lo que va a producir. Cómo se podría evitar esto? Pues haciendo que la salida no sea reversible. Por ejemplo,
// si después del tempering aplicases un hash criptográfico (SHA‑256, por decir uno), ya no habría manera práctica de volver atrás y reconstruir el estado. O,
// más sencillo aún, usar directamente un generador diseñado para seguridad, no para estadística.

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

    MT19937_32(uint32_t seed) : state(n), index(n)
    {
        state[0] = seed;
        for (int i = 1; i < n; ++i)
            state[i] = f * (state[i - 1] ^ (state[i - 1] >> 30)) + i;
    }

    // Constructor que acepta estado ya clonado
    MT19937_32(const std::vector<uint32_t> &cloned_state, int idx = 0)
        : state(cloned_state), index(idx) {}

    uint32_t next()
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

    const std::vector<uint32_t> &get_state() const { return state; }
    int get_index() const { return index; }

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

// Invert y ^= (y >> r)
static uint32_t unxor_right(uint32_t y, int r)
{
    uint32_t x = 0;
    // Empezamos por los bits altos (31..0)
    for (int i = 31; i >= 0; --i)
    {
        uint32_t yi = (y >> i) & 1u;
        uint32_t xi_r = ((i + r) <= 31) ? ((x >> (i + r)) & 1u) : 0u;
        uint32_t xi = yi ^ xi_r;
        x |= (xi << i);
    }
    return x;
}

// Invert y ^= (y << l) & mask
static uint32_t unxor_left_mask(uint32_t y, int l, uint32_t mask)
{
    uint32_t x = 0;
    // Empezamos por los bits bajos (0..31)
    for (int i = 0; i <= 31; ++i)
    {
        uint32_t yi = (y >> i) & 1u;
        uint32_t xi_l = (i - l >= 0) ? ((x >> (i - l)) & 1u) : 0u;
        uint32_t mi = (mask >> i) & 1u;
        uint32_t xi = yi ^ (mi ? xi_l : 0u);
        x |= (xi << i);
    }
    return x;
}

// Aplica las inversiones en orden inverso al tempering
static uint32_t untemper(uint32_t y)
{
    // y ^= (y >> l)
    y = unxor_right(y, MT19937_32::l);
    // y ^= (y << t) & c
    y = unxor_left_mask(y, MT19937_32::t, MT19937_32::c);
    // y ^= (y << s) & b
    y = unxor_left_mask(y, MT19937_32::s, MT19937_32::b);
    // y ^= (y >> u) & d
    // Nota: d=0xFFFFFFFF, la máscara no cambia el patrón; podemos usar unxor_right
    y = unxor_right(y, MT19937_32::u);
    return y;
}

std::optional<uint32_t> crack_seed(uint32_t observed, uint64_t time_of_output,
                                   int min_delay = 40, int max_delay = 1000)
{
    for (int d = min_delay; d <= max_delay; ++d)
    {
        uint32_t candidate = static_cast<uint32_t>(time_of_output - d);
        MT19937_32 test(candidate);
        if (test.next() == observed)
            return candidate;
    }
    return std::nullopt;
}

int main()
{
    // Víctima: generador original
    MT19937_32 victim(5489);

    // Capturamos 624 salidas consecutivas
    std::vector<uint32_t> outputs(MT19937_32::n);
    for (int i = 0; i < MT19937_32::n; ++i)
        outputs[i] = victim.next();

    // Untemper para reconstruir el estado
    std::vector<uint32_t> cloned_state(MT19937_32::n);
    for (int i = 0; i < MT19937_32::n; ++i)
        cloned_state[i] = untemper(outputs[i]);

    // Creamos el clon con el mismo index (el original ha consumido n elementos, así que está en index=n → tras twist volverá a 0)
    MT19937_32 clone(cloned_state, MT19937_32::n);

    // Validación: ambas secuencias deben coincidir a partir de ahora
    for (int i = 0; i < 10; ++i)
    {
        uint32_t a = victim.next();
        uint32_t b = clone.next();
        std::cout << a << " vs " << b << (a == b ? " OK" : " MISMATCH") << "\n";
    }
    return 0;
}