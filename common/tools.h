#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

unsigned char *hex_to_bytes(const char *hex, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    *out_len = hex_len / 2; // Cada 2 caracteres hexadecimales representan un byte
    unsigned char *bytes = (unsigned char *)malloc(*out_len); // Malloc es para reservar memoria dinamicamente

    for (size_t i = 0; i < hex_len; i += 2)
    {
        char byte_str[3] = {hex[i], hex[i + 1], '\0'}; //OJO, se pone el \0 al final para que strtol funcione bien, sino no sabe donde acaba la cadena.
        bytes[i / 2] = (unsigned char)strtol(byte_str, NULL, 16); // Convertimos el string hexadecimal a un byte
    }
    return bytes;
}

char *bytes_to_hex(const unsigned char *bytes, size_t len)
{
    char *hex = (char *)malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++)
    {
        sprintf(hex + (i * 2), "%02x", bytes[i]); // Convertimos cada byte a dos caracteres hexadecimales 
    }
    hex[len * 2] = '\0'; //Recuerda poner el \0 al final para que sea un string valido
    return hex;
}

char *bytes_to_base64(const unsigned char *data, size_t len)
{
    size_t out_len = 4 * ((len + 2) / 3); // Cada 3 bytes se convierten en 4 caracteres base64
    char *out = (char *)malloc(out_len + 1);
    size_t j = 0;

    for (size_t i = 0; i < len; i += 3) // Procesamos 3 bytes a la vez
    {
        unsigned int val = 0;
        int chunk = 0;

        for (int k = 0; k < 3; k++) // Construimos un entero de 24 bits a partir de los 3 bytes
        {
            val <<= 8; //Esto es nuevo, lo de <<=8 es un desplazamiento a la izquierda de 8 bits.
            if (i + k < len)
            {
                val |= data[i + k]; // Si hay un byte disponible, lo añadimos
                chunk++;
            }
        }

        for (int k = 0; k < 4; k++) // Extraemos 4 grupos de 6 bits
        {
            if (k <= chunk) // Si hay datos suficientes, convertimos a base64
            {
                int index = (val >> (18 - 6 * k)) & 0x3F; // Extraemos los 6 bits correspondientes
                out[j++] = base64_table[index]; // Mapeamos a la tabla base64
            }
            else
            {
                out[j++] = '='; // Relleno si no hay suficientes bytes
            }
        }
    }

    out[j] = '\0'; //Recuerda poner el \0 al final para que sea un string valido
    return out;
}

unsigned char *fixed_xor(const unsigned char *buf1, const unsigned char *buf2, size_t len)
{
    unsigned char *result = (unsigned char *)malloc(len);

    for (size_t i = 0; i < len; i++)
    {
        result[i] = buf1[i] ^ buf2[i]; // XOR byte a byte, se hace con el operador ^
    }
    return result;
}

unsigned char *xor_key(const unsigned char *message, size_t len_message, const unsigned char *key, size_t len_key)
{
    unsigned char *result = (unsigned char *)malloc(len_message);

    for (size_t i = 0; i < len_message; i++)
    {
        result[i] = message[i] ^ key[i % len_key]; // XOR con la clave repetida si es necesario
    }

    return result;
}

unsigned int getScore(const unsigned char *buf, size_t len)
{
    int score = 0;
    for (size_t i = 0; i < len; i++)
    {
        char letter = buf[i];
        if (letter == 'e' || letter == 'a' || letter == 'r' ||
            letter == 'i' || letter == 'o' || letter == 't' ||
            letter == 'n' || letter == 's' || letter == ' ')
        {
            score++;
        }
    }
    return score;
}
