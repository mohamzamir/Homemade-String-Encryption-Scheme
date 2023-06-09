#include "unit_tests.h"

TestSuite(student_suite, .timeout=TEST_TIMEOUT);

Test(student_suite, encrypt_empty_plaintext, .description="Should only encrypt EOM") {
    char ciphertext_act[] = "Student test!";
    char *plaintext = "";
    int count_act = encrypt(plaintext, ciphertext_act);
    char *ciphertext_exp = "STUDENt test!";
    int count_exp = 0;
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);

}

Test(student_suite, encrypt_empty_ciphertext, .description="Check if encrypt properly detects not enough space to encode EOM marker") {
    char ciphertext_act[] = "";
    char *plaintext = "Secret Message";
    int count_act = encrypt(plaintext, ciphertext_act);
    char *ciphertext_exp = "";
    int count_exp = -1;
    cr_expect_str_eq(ciphertext_act, ciphertext_exp, "ciphertext was:          %s\nbut it should have been: %s", ciphertext_act, ciphertext_exp);
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(student_suite, decrypt_empty_ciphertext, .description="Check for empty ciphertext") {
    char plaintext_act[] = "*******************";
    char *ciphertext = "";
    int count_act = decrypt(ciphertext, plaintext_act);  
    char *plaintext_exp = "*******************";
    int count_exp = -2;
    cr_expect_str_eq(plaintext_act, plaintext_exp, "plaintext was:           %s\nbut it should have been: %s", plaintext_act, plaintext_exp);
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);

}

Test(student_suite, decrypt_invalid_symbol, .description="Check for -3 error code, where ciphertext has an invalid symbol") {
    char plaintext_act[] = "*******************";
    char *ciphertext = "AAAbAbAAAAAA";
    int count_act = decrypt(ciphertext, plaintext_act);  
    char *plaintext_exp = "*******************";
    int count_exp = -3;
    cr_expect_str_eq(plaintext_act, plaintext_exp, "plaintext was:           %s\nbut it should have been: %s", plaintext_act, plaintext_exp);
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);
}

Test(student_suite, decrypt_empty_plaintext, .description="Check for -1 error code, when plaintext does not have space to store symbol") {
   char plaintext_act[] = "";
    char *ciphertext = "AbAbAbAAAAAA"; // 2 EOM
    int count_act = decrypt(ciphertext, plaintext_act);  
    char *plaintext_exp = "";
    int count_exp = -1;
    cr_expect_str_eq(plaintext_act, plaintext_exp, "plaintext was:           %s\nbut it should have been: %s", plaintext_act, plaintext_exp);
    cr_expect_eq(count_act, count_exp, "Return value was %d, but it should have been %d.\n", count_act, count_exp);

}


