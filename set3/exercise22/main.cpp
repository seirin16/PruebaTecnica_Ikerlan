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
// Enunciado del ejercicio 22: Crack an MT19937 seed

// Make sure your MT19937 accepts an integer seed value. Test it (verify that you're getting the same sequence of outputs given a seed).

// Write a routine that performs the following operation:

//     Wait a random number of seconds between, I don't know, 40 and 1000.
//     Seeds the RNG with the current Unix timestamp
//     Waits a random number of seconds again.
//     Returns the first 32 bit output of the RNG.

// You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although you're missing some of the fun of this exercise if you do that.

// From the 32 bit RNG output, discover the seed.

//------------------------------------------------------------------------------------------------------------------

// 1. La "víctima" espera un número aleatorio de segundos (entre 40 y 1000).
// 2. Siembra el PRNG MT19937 con el timestamp Unix actual (en segundos).
// 3. Vuelve a esperar entre 40 y 1000 segundos.
// 4. Devuelve el primer número de 32 bits generado por el PRNG.
//
// Problema de seguridad:
// ----------------------
// - El adversario conoce aproximadamente el momento en que se generó el número.
// - Como el timestamp cambia lentamente (segundos) y el rango de espera es pequeño,
//   el espacio de semillas posibles es reducido (solo unas centenas o miles).
// - Basta con probar todas las semillas candidatas en ese rango y comprobar cuál
//   reproduce la salida observada.
//
// Enfoque de la solución:
// -----------------------
// - Implementamos MT19937-32 con inicialización por semilla entera.
// - Simulamos la rutina vulnerable que siembra con el timestamp y devuelve un número.
// - Implementamos un "cracker" que, dado el número observado y el momento aproximado,
//   recorre hacia atrás los posibles timestamps y compara la primera salida de cada
//   semilla con el número observado.
// - Cuando encuentra coincidencia, hemos descubierto la semilla real.


class MT19937_32 {
public:
    static constexpr int n = 624, m = 397;
    static constexpr uint32_t a = 0x9908B0DF;
    static constexpr uint32_t u = 11, d = 0xFFFFFFFF;
    static constexpr uint32_t s = 7,  b = 0x9D2C5680;
    static constexpr uint32_t t = 15, c = 0xEFC60000;
    static constexpr uint32_t l = 18;
    static constexpr uint32_t f = 1812433253;

    MT19937_32(uint32_t seed) : state(n), index(n) {
        state[0] = seed;
        for (int i = 1; i < n; ++i)
            state[i] = f * (state[i-1] ^ (state[i-1] >> 30)) + i;
    }

    uint32_t next() {
        if (index >= n) twist();
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

    void twist() {
        static constexpr uint32_t UPPER_MASK = 0x80000000u;
        static constexpr uint32_t LOWER_MASK = 0x7FFFFFFFu;
        for (int i = 0; i < n; ++i) {
            uint32_t x = (state[i] & UPPER_MASK) | (state[(i+1)%n] & LOWER_MASK);
            uint32_t xA = x >> 1;
            if (x & 1U) xA ^= a;
            state[i] = state[(i + m) % n] ^ xA;
        }
        index = 0;
    }
};

uint32_t vulnerable_output() {
    using clock = std::chrono::system_clock;
    auto now = std::chrono::time_point_cast<std::chrono::seconds>(clock::now()).time_since_epoch().count();

    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(40, 1000);

    int delta1 = dist(rng);
    uint32_t seed = static_cast<uint32_t>(now + delta1);

    int delta2 = dist(rng);
    (void)delta2; // solo simula la espera; no afecta al seed

    MT19937_32 prng(seed);
    return prng.next();
}

std::optional<uint32_t> crack_seed(uint32_t observed, uint64_t time_of_output,
                                   int min_delay = 40, int max_delay = 1000) {
    for (int d = min_delay; d <= max_delay; ++d) {
        uint32_t candidate = static_cast<uint32_t>(time_of_output - d);
        MT19937_32 test(candidate);
        if (test.next() == observed) return candidate;
    }
    return std::nullopt;
}

int main() {
    // Simula la víctima
    using clock = std::chrono::system_clock;
    auto now = std::chrono::time_point_cast<std::chrono::seconds>(clock::now()).time_since_epoch().count();

    // Genera salida vulnerable
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(40, 1000);
    int delta1 = dist(rng);
    uint32_t seed = static_cast<uint32_t>(now + delta1);
    int delta2 = dist(rng);
    uint64_t time_of_output = now + delta1 + delta2;

    MT19937_32 victim(seed);
    uint32_t observed = victim.next();

    // Atacante: crackea el seed sabiendo time_of_output
    auto cracked = crack_seed(observed, time_of_output);
    if (cracked) {
        std::cout << "Seed crackeado: " << *cracked << " (real: " << seed << ")\n";
    } else {
        std::cout << "No se pudo crackear el seed.\n";
    }
    return 0;
}