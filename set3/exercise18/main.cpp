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

#include "tools.h"
#include "tools_cpp.h"

//-----------------------------------------------------------------------------------------------------------------
// Enunciado del ejercicio 18: Implement CTR, the stream cipher mode

// The string:

// L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==

// ... decrypts to something approximating English in CTR mode, which is an AES block cipher mode that turns AES into a stream cipher, with the following parameters:

//       key=YELLOW SUBMARINE
//       nonce=0
//       format=64 bit unsigned little endian nonce,
//              64 bit little endian block count (byte count / 16)

// CTR mode is very simple.

// Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing a 16 byte block of keystream, which is XOR'd against the plaintext.

// For instance, for the first 16 bytes of a message with these parameters:

// keystream = AES("YELLOW SUBMARINE",
//                 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

// ... for the next 16 bytes:

// keystream = AES("YELLOW SUBMARINE",
//                 "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")

// ... and then:

// keystream = AES("YELLOW SUBMARINE",
//                 "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")

// CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing keystream and stop generating keystream.

// Decryption is identical to encryption. Generate the same keystream, XOR, and recover the plaintext.

// Decrypt the string at the top of this function, then use your CTR function to encrypt and decrypt other things.
// This is the only block cipher mode that matters in good code.

// Most modern cryptography relies on CTR mode to adapt block ciphers into stream ciphers, because most of what we want to encrypt is better described as a stream than as a sequence of blocks. Daniel Bernstein once quipped to Phil Rogaway that good cryptosystems don't need the "decrypt" transforms. Constructions like CTR are what he was talking about.

//------------------------------------------------------------------------------------------------------------------

// Este ejercicio basicamente añade un nuevo modo que es el CTR
// Tiene algunas diferencias con ECB y el CBC y es que basicamente se desprocupa por el padding al mismo tiempo que es bastante
// más seguro que estos dos. Actualmente se utiliza pero normalmente a través de AES-GCM que incluye CTR + autenticación

// La idea es clara, en lugar de cifrar los datos directamente, CTR cifra un contador y luego hace XOR con el plaintext:
// Ciphertext = Plaintext ⊕ AES(Key, Nonce || Counter)
// Nonce son 8 bytes y Couter otros 8
// Cosas asi: El Nonce se mantiene flijo mientras que el contador va aumentando (en este caso nonce es siempre 0)

// Mola pq el mismo metodo te sirve tanto para cifrar como para descifrar

//Yo creo que el problema aqui es conocer nonce

int main()
{
    const std::string base64_input =
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

    std::vector<unsigned char> ciphertext = base64_to_bytes(base64_input);
    const std::string key_str = "YELLOW SUBMARINE";
    const unsigned char* key = reinterpret_cast<const unsigned char*>(key_str.data());

    auto plaintext = aes_ctr_crypt(ciphertext, key, 0); 

    std::string result(plaintext.begin(), plaintext.end());
    std::cout << "Texto descifrado:\n" << result << "\n";

    // Prueba de cifrado inverso
    auto reciphered = aes_ctr_crypt(plaintext, key, 0);
    std::string result2(reciphered.begin(), reciphered.end());

    std::cout << "Texto cifrado:\n" << result2 << "\n";

    std::cout << (reciphered == ciphertext ? "[OK] Recifrado coincide con original\n" : "[FAIL] Recifrado no coincide\n");

    return 0;
}