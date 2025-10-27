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
// Enunciado del ejercicio 15: PKCS#7 padding validation

// Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

// The string:

// "ICE ICE BABY\x04\x04\x04\x04"

// ... has valid padding, and produces the result "ICE ICE BABY".

// The string:

// "ICE ICE BABY\x05\x05\x05\x05"

// ... does not have valid padding, nor does:

// "ICE ICE BABY\x01\x02\x03\x04"

// If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

// Crypto nerds know where we're going with this. Bear with us.

//------------------------------------------------------------------------------------------------------------------

// Este ejercicio es la coninuacion del pkcs7.
// Simplemente hay que comprobar que el padding es correcto y si lo es, quitarlo.

// Como sabemos lo que hay que quitar, simplemente comprobamos que los ultimos n bytes son iguales a n.
// Como ejemplo, si el ultimo byte es 0x04, los ultimos 4 bytes deben ser 0x04 0x04 0x04 0x04.
// Si no es asi, lanzamos una excepcion.

int main()
{
    std::string s1 = "ICE ICE BABY\x04\x04\x04\x04";
    std::vector<unsigned char> v1(s1.begin(), s1.end());

    try
    {
        auto unpadded = pkcs7_unpad(v1, 16);
        std::cout << "OK: " << std::string(unpadded.begin(), unpadded.end()) << "\n";
    }
    catch (const std::exception &e)
    {
        std::cout << "Error: " << e.what() << "\n";
    }

    std::string s2 = "ICE ICE BABY\x05\x05\x05\x05"; //Esto da error porque el padding es incorrecto
    std::vector<unsigned char> v2(s2.begin(), s2.end());

    try
    {
        auto unpadded = pkcs7_unpad(v2, 16);
        std::cout << "OK: " << std::string(unpadded.begin(), unpadded.end()) << "\n";
    }
    catch (const std::exception &e)
    {
        std::cout << "Error: " << e.what() << "\n";
    }

    std::string s3 = "ICE ICE BABYBAB\x01";
    std::vector<unsigned char> v3(s3.begin(), s3.end());

    try
    {
        auto unpadded = pkcs7_unpad(v3, 16);
        std::cout << "OK: " << std::string(unpadded.begin(), unpadded.end()) << "\n";
    }
    catch (const std::exception &e)
    {
        std::cout << "Error: " << e.what() << "\n";
    }

    return 0;
}