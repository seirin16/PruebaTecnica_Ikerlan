#include <stdio.h>
#include <string.h>

#include "tools.h"


int main()
{
    unsigned char* string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    for (int i = 0; i < strlen(string); i+=2) {
        // Convertir cada par de caracteres hexadecimales a un byte
        char byteString[3] = {string[i], string[i+1], '\0'};
        unsigned char byte = (unsigned char) strtol(byteString, NULL, 16);
        printf("Byte %d: %x\n", i / 2, byte);
    }

    hello_world();
    return 0;
}