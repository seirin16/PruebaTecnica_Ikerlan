#include <stdio.h>
#include <string.h>

#include "tools.h"

//-----------------------------------------------------------------------------------------------------------------
// Enunciado del ejercicio 1: Convert hex to base64

// The string:

// 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

// Should produce:

// SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

// So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
// Cryptopals Rule

// Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.
//------------------------------------------------------------------------------------------------------------------

// Aqui tenemos que entender los conceptos de hexadecimal, bytes y base64.
// Hecadecimal es una representacion en base 16 de los datos, cada dos caracteres hexadecimales representan un byte (8 bits).
// Base64 es una representacion en base 64 de los datos, cada 3 bytes (24 bits) se dividen en 4 grupos de 6 bits, y cada grupo se representa con un caracter de la tabla base64.

// Hay que transformar el hexadecimal en bytes. Para ello hay varias opciones.
// La primera era la de poner 0x y a vivir, en cambio, yo prefiero usar strtol para conseguirlo.

int main()
{
    unsigned char *string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    size_t bytes_len;

    // Convertimos el hexadecimal en bytes (si printeamos los bytes veremos el mensaje bien, entiende que un byte es un caracter)
    unsigned char *bytes = hex_to_bytes(string, &bytes_len);

    // Convertimos los bytes en base64 (3 grupos de 3 bytes -> 4 grupoes de 6 bits).
    char *base64 = bytes_to_base64(bytes, bytes_len);

    printf("Hex: %s\n", string);
    printf("Bytes: %s\n", bytes);
    printf("Base64: %s\n", base64);

    // Liberamos la memoria, muy importante en C. Siempre que se haga un malloc hay que hacer un free.
    free(bytes);
    free(base64);
    return 0;
}