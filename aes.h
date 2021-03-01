#ifndef AES_H
#define AES_H

// Encrypts and decrypt data using aes ctr mode and sha3_256 for key generation

// The original source comes from
// sha3:         https://github.com/brainhub/SHA3IUF
// aes:          https://github.com/kokke/tiny-AES-c

// Encryption output size must be at least 32 bytes larger than input size
// Decryption output size must be at least input size - 32 bytes
// The first 12 bytes containes the salt
// The next 16 bytes containes the iv
// Ant the last 4 bytes containes the adler checksum
// They are encrypted with the key from password
// Then data is encrypted with the key from password and salt
// Keys, iv, salt are set to 0 before exiting functions

#include <stdbool.h>

bool sha3_keccak_256(const char* in, int in_size, char* out, int out_size_min32, int iterations = 1);
bool decrypt(const char* in, int in_size, char* out, int out_size, const char* password, int password_iterations = 1);
bool encrypt(const char* in, int in_size, char* out, int out_size, const char* password, int password_iterations = 1);

#endif
