#include "bacon.h"

int main() {
    char plaintext_act[] = "@@@@@@@@@";
    for (unsigned int i = 0; i < strlen(plaintext_act); i++)
        plaintext_act[i] = (char)(rand() % 200 + 33);
    char *ciphertext = "i Can StoRe tHRee CHArACTERS! Yes!";
    decrypt(ciphertext, plaintext_act);  
}