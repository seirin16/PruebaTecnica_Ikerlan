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

unsigned char* hex_to_bytes(const char* hex, size_t* out_len) {
    size_t hex_len = strlen(hex);  
    *out_len = hex_len / 2; 
    unsigned char* bytes = (unsigned char*) malloc(*out_len);

    for (size_t i = 0; i < hex_len; i += 2) {  
        char byte_str[3] = {hex[i], hex[i+1], '\0'};  
        bytes[i / 2] = (unsigned char) strtol(byte_str, NULL, 16);  
    }
    return bytes;  
}

const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* bytes_to_base64(const unsigned char* data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char* out = malloc(out_len + 1); 
    size_t j = 0;

    for (size_t i = 0; i < len; i += 3) {
        unsigned int val = 0;
        int chunk = 0;

        for (int k = 0; k < 3; k++) {
            val <<= 8; 
            if (i + k < len) { 
                val |= data[i + k];
                chunk++;
            }
        }

        for (int k = 0; k < 4; k++) {
            if (k <= chunk) {
                int index = (val >> (18 - 6*k)) & 0x3F; 
                out[j++] = base64_table[index];
            } else {
                out[j++] = '='; 
            }
        }
    }

    out[j] = '\0'; 
    return out;
}


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