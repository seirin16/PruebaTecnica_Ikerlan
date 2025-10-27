#include <stdio.h>

#include "tools.h"

//-----------------------------------------------------------------------------------------------------------------
// Enunciado del ejercicio 2: Fixed XOR

// Write a function that takes two equal-length buffers and produces their XOR combination.

// If your function works properly, then when you feed it the string:

// 1c0111001f010100061a024b53535009181c

// ... after hex decoding, and when XOR'd against:

// 686974207468652062756c6c277320657965

// ... should produce:

// 746865206b696420646f6e277420706c6179
//------------------------------------------------------------------------------------------------------------------

//El XOR es algo trivial, es como cuando hablamos de AND y OR.
//En este caso, tenemos que hacer un XOR entre dos buffers de bytes.
//Para ello, primero tenemos que convertir los strings hexadecimales a bytes.
//Luego, hacemos el XOR byte a byte (XOR es una operacion bit a bit 1 XOR 1 = 0, 0 XOR 0 = 0, 1 XOR 0 = 1, 0 XOR 1 = 1).
//Finalmente, convertimos el resultado a hexadecimal para mostrarlo.

int main() {
    const char* hex1 = "1c0111001f010100061a024b53535009181c";
    const char* hex2 = "686974207468652062756c6c277320657965";

    size_t len1, len2;
    unsigned char* bytes1 = hex_to_bytes(hex1, &len1);
    unsigned char* bytes2 = hex_to_bytes(hex2, &len2);

    unsigned char* xored = fixed_xor(bytes1, bytes2, len1); // Asumimos que len1 == len2 ya que sino no funcionaria

    printf("Resultado XOR: %s\n", xored);

    char* result_hex = bytes_to_hex(xored, len1);

    printf("Resultado XOR: %s\n", result_hex);

    free(bytes1);
    free(bytes2);
    free(xored);
    free(result_hex);

    return 0;
}