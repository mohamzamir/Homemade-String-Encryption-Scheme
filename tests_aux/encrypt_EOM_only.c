#include "bacon.h"

int main() {
    char ciphertext_act[] = "Too Short 2022";
    char *plaintext = "Stony Brook University";
    encrypt(plaintext, ciphertext_act);
}