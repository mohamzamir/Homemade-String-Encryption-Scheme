#include "bacon.h"

int main() {
    char ciphertext_act[] = "I can store three characters! Yes!";
    char *plaintext = "Stony Brook University";
    encrypt(plaintext, ciphertext_act);
}