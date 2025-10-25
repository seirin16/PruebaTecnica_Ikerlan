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
// Enunciado del ejercicio 14: Byte-at-a-time ECB decryption (Harder)

// Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

// AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

// Same goal: decrypt the target-bytes.
// Stop and think for a second.

// What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

// Think "STIMULUS" and "RESPONSE".

//------------------------------------------------------------------------------------------------------------------



int main()
{

    return 0;
}