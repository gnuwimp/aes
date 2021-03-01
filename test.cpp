#include "aes.cpp"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int test_sha3_256();
int test_adler32();
int test_aes_ctr();

int main() {
    srand(time(NULL));

    {
        printf("testing adler32\n");
        uint32_t adler = _aes_adler32("The quick brown fox jumps over the lazy dog", 43);
        assert(adler == 1541148634);
    }

    {
        printf("testing aes_ctr\n");

        uint8_t key[32] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
        uint8_t in[64]  = { 0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
                            0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
                            0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
                            0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6 };
        uint8_t in2[64] = { 0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
                            0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
                            0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
                            0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6 };
        uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
        uint8_t out[64] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };

        {
            struct AES_ctx ctx;
            AES_init_ctx_iv(&ctx, key, iv);
            AES_CTR_xcrypt_buffer(&ctx, in, 64);
            assert(memcmp((char*) out, (char*) in, 64) == 0);
        }

        {
            struct AES_ctx ctx;
            AES_init_ctx_iv(&ctx, key, iv);
            AES_CTR_xcrypt_buffer(&ctx, in, 64);
            assert(memcmp((char*) in2, (char*) in, 64) == 0);
        }
    }

    {
        const char* TEXT = "The quick brown fox jumps over the lazy dog";
        const unsigned char SHA3[32] = { 0x4d, 0x74, 0x1b, 0x6f, 0x1e, 0xb2, 0x9c, 0xb2, 0xa9, 0xb9, 0x91, 0x1c, 0x82, 0xf5, 0x6f, 0xa8, 0xd7, 0x3b, 0x04, 0x95, 0x9d, 0x3d, 0x9d, 0x22, 0x28, 0x95, 0xdf, 0x6c, 0x0b, 0x28, 0xaa, 0x15 };
        char sha3[32];

        sha3_keccak_256(TEXT, strlen(TEXT), sha3, 32, 1);
        assert(memcmp(SHA3, sha3, 32) == 0);
    }

    {
        printf("testing encrypt and decrypt\n");

        const char* const TEXT = "These violent delights have violent ends\nAnd in their triump die, like fire and powder\nWhich, as they kiss, consume";
        const int         len  = strlen(TEXT) + 1;
        char*             enc  = (char*) malloc(len + 32);
        char*             dec  = (char*) malloc(len);
        char              old1 = 0;
        char              old2 = 0;

        { // Encrypt failure
            assert(false == encrypt(NULL, len, enc, len + 32, "abcdef", 1));
            assert(false == encrypt(TEXT, 0, enc, len + 32, "abcdef", 1));
            assert(false == encrypt(TEXT, len, NULL, len + 32, "abcdef", 1));
            assert(false == encrypt(TEXT, len, enc, len + 31, "abcdef", 1));
            assert(false == encrypt(TEXT, len, enc, len + 32, NULL, 1));
            assert(false == encrypt(TEXT, len, enc, len + 32, "", 1));
            assert(false == encrypt(TEXT, len, enc, len + 32, "abc", 0));
        }

        { // Encrypt
            assert(true == encrypt(TEXT, len, enc, len + 32, "åäöÜÅÄÖ", 1));
            FILE* f = fopen("enc.bin", "wb"); fwrite(enc, len + 32, 1, f); fclose(f);
        }

        { // Decrypt failure
            assert(false == decrypt(NULL, len + 32, dec, len, "abcdef", 1));
            assert(false == decrypt(enc, 32, dec, len, "abcdef", 1));
            assert(false == decrypt(enc, len + 32, NULL, len, "abcdef", 1));
            assert(false == decrypt(enc, len + 32, dec, len - 1, "abcdef", 1));
            assert(false == decrypt(enc, len + 32, dec, len, "abCdef", 1));
            assert(false == decrypt(enc, len + 32, dec, len, "", 1));
            assert(false == decrypt(enc, len + 32, dec, len, "abc", 0));
            assert(false == decrypt(enc, len + 32, dec, len, "åäöÜÅÄÖ", 2));

            old1   = enc[0];
            old2   = enc[1];
            enc[0] = 0;
            enc[1] = 0;
            assert(false == decrypt(enc, len + 32, dec, len, "åäöÜÅÄÖ", 1));

            enc[0]  = old1;
            enc[1]  = old2;
            old1    = enc[16];
            old2    = enc[17];
            enc[16] = 0;
            enc[17] = 0;
            assert(false == decrypt(enc, len + 32, dec, len, "åäöÜÅÄÖ", 1));

            enc[16] = old1;
            enc[17] = old2;
            old1    = enc[29];
            old2    = enc[30];
            enc[29] = 0;
            enc[30] = 0;
            assert(false == decrypt(enc, len + 32, dec, len, "åäöÜÅÄÖ", 1));

            enc[29] = old1;
            enc[30] = old2;
            old1    = enc[40];
            old2    = enc[41];
            enc[40] = 0;
            enc[41] = 0;
            assert(false == decrypt(enc, len + 32, dec, len, "åäöÜÅÄÖ", 1));
            enc[40] = old1;
            enc[41] = old2;
        }

        { // Decrypt
            assert(true == decrypt(enc, len + 32, dec, len, "åäöÜÅÄÖ", 1));
            assert(strcmp(TEXT, dec) == 0);
            FILE* f = fopen("dec.bin", "wb"); fwrite(dec, len, 1, f); fclose(f);
        }

        free(enc);
        free(dec);
    }

    {
        const char* PASSWORD = "abc";
        const char* TEXT = "Hello World";
        const int TEXT_LENGTH = strlen(TEXT) + 1;
        char enc[100];
        char dec[100];

        encrypt(TEXT, TEXT_LENGTH, enc, TEXT_LENGTH + 32, PASSWORD, 1);
        decrypt(enc, TEXT_LENGTH + 32, dec, TEXT_LENGTH, PASSWORD, 1);
        printf("Input text is <%s>, decrypted text is <%s>\n", TEXT, dec);
    }

    printf("tests ok\n");
}
