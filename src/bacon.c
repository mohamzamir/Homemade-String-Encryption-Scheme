#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>

char char_to_code(char c)
{
	if(isalpha(c))					// 0-25
		return c - 'A';
	else if(isdigit(c))				// 40-49
		return c - '0' + 40;
	else if(c >= ' ' && c <= ')')	// 26-35
		return c - ' ' + 26;
	else if(c >= ',' && c <= '/')	// 36-39
		return c - ',' + 36;
	else if(c == '?')				// 52
		return 52;
	else if(c == '\0')				// 63
		return 63;
	else							// 50-51
		return c - ':' + 50;
}

char code_to_char(char code)
{
	if(code >= 0 && code <= 25)
		return 'A' + code;
	else if(code >= 26 && code <= 35)
		return ' ' + code - 26;
	else if(code >= 36 && code <= 39)
		return ',' + code - 36;
	else if(code >= 40 && code <= 49)
		return '0' + code - 40;
	else if(code >= 50 && code <= 51)
		return ':' + code - 50;
	else if(code == 52)
		return '?';
	else if(code == 63)
		return '\0'; // \0 is a stand-in for the EOM marker
	else
		return -1;
}

int encrypt(const char *plaintext, char *ciphertext)
{
	int num_chars = strlen(plaintext);

	// Figure out how many a's and b's we can actually encode in total
	int letter_count = 0;
	char c;
	for(int i = 0; (c = ciphertext[i]) != '\0'; i++)
		if(isalpha(c))
			letter_count++;
	
	// If we don't have space for even an EOM marker, return -1
	if(letter_count < 6)
		return -1;
	
	int num_encoded = 0;
	// While we have space for another symbol and we haven't encoded all the symbols yet
	while(letter_count >= 6 && num_encoded <= num_chars)
	{
		char code;
		// If we don't have enough letters left to encode two more symbols, or we've encoded all symbols already,
		// encode the EOM marker
		if(letter_count < 12 || num_encoded == num_chars) // EOM code
			code = 0b111111;
		else // Otherwise, encode the code
		{
			c = toupper(plaintext[num_encoded]);
			code = char_to_code(c);
		}

		num_encoded++;
		
		for(int i = 5; i >= 0; i--)
		{
			// Find next letter in ciphertext
			while(!isalpha(ciphertext[0]))
				ciphertext++;

			if(code & (1 << i))
				ciphertext[0] = toupper(ciphertext[0]);
			else
				ciphertext[0] = tolower(ciphertext[0]);

			ciphertext++;
		}

		letter_count -= 6;
	}

	return num_encoded - 1; // num_encoded should not include EOM
}

int decrypt(const char *ciphertext, char *plaintext)
{
	int max_decode = strlen(plaintext);
	if(max_decode == 0)
		return -1;

	int letter_count = 0;
	char c;
	for(int i = 0; (c = ciphertext[i]) != '\0'; i++)
		if(isalpha(c))
			letter_count++;
	
	bool invalid_code = false; // Keep track of if we encounter an invalid code

	int num_decoded = 0;

	// Allocate memory for decoded symbols
	char *codes = (char *)malloc((letter_count / 6) * sizeof(char));

	int code = -1;
	// While we can still decode a symbol and we haven't encountered the EOM marker
	while(letter_count > 6 && code != 0b111111)
	{
		code = 0;
		for(int i = 5; i >= 0; i--)
		{
			while(!isalpha(ciphertext[0]))
				ciphertext++;

			// If there is an uppercase letter, we set the bit in the code
			if(ciphertext[0] >= 'A' && ciphertext[0] <= 'Z')
				code |= 1 << i;

			ciphertext++;
		}

		codes[num_decoded++] = code_to_char(code);
		if(codes[num_decoded - 1] == -1) // code_to_char returns -1 if there is an invalid code
			invalid_code = true;
	}

	// If we never encountered the EOM marker, return -2
	if(code != 0b111111)
	{
		free(codes);
		return -2;
	}

	// If we encountered an invalid code, return -3
	if(invalid_code)
	{
		free(codes);
		return -3;
	}

	// Copy characters from codes to plaintext
	for(num_decoded = 0; num_decoded < strlen(codes) && num_decoded < max_decode; num_decoded++)
		plaintext[num_decoded] = codes[num_decoded];
	
	plaintext[num_decoded] = '\0';

	free(codes);
	return num_decoded; // Don't include EOM marker
}
