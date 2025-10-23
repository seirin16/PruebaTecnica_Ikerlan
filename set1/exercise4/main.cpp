#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cctype>
#include <algorithm>

#include "tools.h"

//-----------------------------------------------------------------------------------------------------------------
// Enunciado del ejercicio 4: Detect single-character XOR

// One of the 60-character strings in this file has been encrypted by single-character XOR.

// Find it.

// (Your code from #3 should help.)

//------------------------------------------------------------------------------------------------------------------


int main() {

    std::ifstream file("data.txt");

    std::string line;

    while (std::getline(file, line)) {
        auto bytes = hex_to_bytes(line, );

        
    }

    return 0;
}