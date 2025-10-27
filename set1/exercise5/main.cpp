#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <algorithm>

#include "tools.h"

//-----------------------------------------------------------------------------------------------------------------
// Enunciado del ejercicio 5: Implement repeating-key XOR

// Here is the opening stanza of an important work of the English language:

// Burning 'em, if you ain't quick and nimble
// I go crazy when I hear a cymbal

// Encrypt it, under the key "ICE", using repeating-key XOR.

// In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

// It should come out to:

// 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
// a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

// Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.

//------------------------------------------------------------------------------------------------------------------

//Contrario que los ejercicios anteriores, aqui no hay que romper ningun cifrado,
//sino que hay que implementar el cifrado XOR con clave repetida.

//Cual es la magia del XOR: Que al igual que sirve para descifrar, sirve para cifrar.
//Si aplicas el XOR dos veces con la misma clave, recuperas el mensaje original.

int main()
{
    std::string plaintext =
        "Burning 'em, if you ain't quick and nimble\n"
        "I go crazy when I hear a cymbal";
    std::string key = "ICE";

    unsigned char *ciphertext = xor_key(reinterpret_cast<const unsigned char *>(plaintext.c_str()), plaintext.length(),
                                        reinterpret_cast<const unsigned char *>(key.c_str()), key.length());

    char *hex = bytes_to_hex(ciphertext, plaintext.length());
    std::cout << "Cifrado: " << hex << "\n";

    unsigned char *decryptext = xor_key(
        ciphertext,
        plaintext.length(),
        reinterpret_cast<const unsigned char *>(key.c_str()),
        key.length());

    std::cout << "Descifrado: " << decryptext << "\n";

    free(ciphertext);
    free(hex);
    free(decryptext);
    return 0;
}