#include <stdio.h>

#include "tools.h"

//-----------------------------------------------------------------------------------------------------------------
// Enunciado del ejercicio 3: Single-byte XOR cipher

// The hex encoded string:

// 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

// ... has been XOR'd against a single character. Find the key, decrypt the message.

// You can do this by hand. But don't: write code to do it for you.

// How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
// Achievement Unlocked

// You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.
//-----------------------------------------------------------------------------------------------------------------

int main()
{
      const char *string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

      unsigned int i = 0x00333231;
      printf(" %x\n", i);
      printf(" %s\n", (unsigned char *)&i);

      size_t len1;

      unsigned char *message = hex_to_bytes(string, &len1);

      int max_score = 0;
      char *solution;

      for (unsigned int c = 0; c < 256; c++)
      {

            unsigned char byte = (unsigned char)c;

            unsigned char *response = xor_key(message, len1, &byte, 1);

            int score = getScore(response, len1);

            if (score > max_score)
            {
                  max_score = score;
                  solution = response;
            }
            else
            {
                  free(response);
            }
      }

      printf(" %s\n", solution);

      return 0;
}