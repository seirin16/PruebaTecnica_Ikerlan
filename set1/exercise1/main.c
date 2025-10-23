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



int main()
{
    unsigned char* string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    size_t bytes_len;

    unsigned char* bytes = hex_to_bytes(string, &bytes_len);

    char* base64 = bytes_to_base64(bytes, bytes_len);

    printf("Hex: %s\n", string);
    printf("Base64: %s\n", base64);

    free(bytes);
    free(base64);
    return 0;
}