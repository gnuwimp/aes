// Encrypts and decrypt data using aes ctr mode and sha3_keccak_256 for key generation

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

#if defined(_WIN32)
    #define _CRT_RAND_S
    #include <Shlobj.h>
#elif defined(__linux__)
    #include <sys/random.h>
#elif defined(__APPLE__)
#else
    #error "unknown platform in aes.c"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Works when compiled for either 32-bit or 64-bit targets, optimized for
// 64 bit.
//
// Canonical implementation of Init/Update/Finalize for SHA-3 byte input.
//
// SHA3-256, SHA3-384, SHA-512 are implemented. SHA-224 can easily be added.
//
// Based on code from http://keccak.noekeon.org/ .
//
// I place the code that I wrote into public domain, free to use.
//
// I would appreciate if you give credits to this work if you used it to
// write or test * your code.
//
// Aug 2015. Andrey Jivsov. crypto@brainhub.org

#define SHA3_KECCAK_SPONGE_WORDS (((1600)/8)/sizeof(uint64_t))

typedef struct sha3_context_ {
    uint64_t saved;
    union {
        uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
        uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
    };
    unsigned byteIndex;
    unsigned wordIndex;
    unsigned capacityWords;
} sha3_context;

enum SHA3_FLAGS {
    SHA3_FLAGS_NONE=0,
    SHA3_FLAGS_KECCAK=1
};

enum SHA3_RETURN {
    SHA3_RETURN_OK=0,
    SHA3_RETURN_BAD_PARAMS=1
};

typedef enum SHA3_RETURN sha3_return_t;

#define SHA3_USE_KECCAK_FLAG 0x80000000
#define SHA3_CW(x) ((x) & (~SHA3_USE_KECCAK_FLAG))
#define SHA3_CONST(x) x##L
#define SHA3_ROTL64(x, y) (((x) << (y)) | ((x) >> ((sizeof(uint64_t)*8) - (y))))
#define KECCAK_ROUNDS 24

static const uint64_t keccakf_rndc[24] = {
    SHA3_CONST(0x0000000000000001UL), SHA3_CONST(0x0000000000008082UL),
    SHA3_CONST(0x800000000000808aUL), SHA3_CONST(0x8000000080008000UL),
    SHA3_CONST(0x000000000000808bUL), SHA3_CONST(0x0000000080000001UL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008009UL),
    SHA3_CONST(0x000000000000008aUL), SHA3_CONST(0x0000000000000088UL),
    SHA3_CONST(0x0000000080008009UL), SHA3_CONST(0x000000008000000aUL),
    SHA3_CONST(0x000000008000808bUL), SHA3_CONST(0x800000000000008bUL),
    SHA3_CONST(0x8000000000008089UL), SHA3_CONST(0x8000000000008003UL),
    SHA3_CONST(0x8000000000008002UL), SHA3_CONST(0x8000000000000080UL),
    SHA3_CONST(0x000000000000800aUL), SHA3_CONST(0x800000008000000aUL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008080UL),
    SHA3_CONST(0x0000000080000001UL), SHA3_CONST(0x8000000080008008UL)
};

static const unsigned keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1
};

static void keccakf(uint64_t s[25]) {
    unsigned int i, j, round;
    uint64_t t, bc[5];

    for(round = 0; round < KECCAK_ROUNDS; round++) {
        for(i = 0; i < 5; i++) {
            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
        }

        for(i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);

            for(j = 0; j < 25; j += 5) {
                s[j + i] ^= t;
            }
        }

        t = s[1];
        for(i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = s[j];
            s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        for(j = 0; j < 25; j += 5) {
            for(i = 0; i < 5; i++) {
                bc[i] = s[j + i];
            }

            for(i = 0; i < 5; i++) {
                s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        s[0] ^= keccakf_rndc[round];
    }
}

static sha3_return_t sha3_Init(void *priv, unsigned bitSize) {
    sha3_context *ctx = (sha3_context *) priv;

    if( bitSize != 256 && bitSize != 384 && bitSize != 512 ) {
        return SHA3_RETURN_BAD_PARAMS;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->capacityWords = 2 * bitSize / (8 * sizeof(uint64_t));
    return SHA3_RETURN_OK;
}

static enum SHA3_FLAGS sha3_SetFlags(void *priv, enum SHA3_FLAGS flags) {
    sha3_context *ctx = (sha3_context *) priv;

    int a = flags;
    a &= SHA3_FLAGS_KECCAK;
    flags = (enum SHA3_FLAGS) a;

    ctx->capacityWords |= (flags == SHA3_FLAGS_KECCAK ? SHA3_USE_KECCAK_FLAG : 0);
    return flags;
}

static void sha3_Update(void *priv, void const *bufIn, size_t len) {
    sha3_context *ctx = (sha3_context *) priv;
    unsigned old_tail = (8 - ctx->byteIndex) & 7;
    size_t words;
    unsigned tail;
    size_t i;
    const uint8_t *buf = (const uint8_t*) bufIn;

    if (len < old_tail) {
        while (len--) {
            ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
        }

        return;
    }

    if (old_tail) {
        len -= old_tail;

        while (old_tail--) {
            ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
        }

        ctx->s[ctx->wordIndex] ^= ctx->saved;
        ctx->byteIndex = 0;
        ctx->saved = 0;

        if (++ctx->wordIndex == (SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx->capacityWords))) {
            keccakf(ctx->s);
            ctx->wordIndex = 0;
        }
    }

    words = len / sizeof(uint64_t);
    tail = len - words * sizeof(uint64_t);

    for(i = 0; i < words; i++, buf += sizeof(uint64_t)) {
        const uint64_t t = (uint64_t) (buf[0]) |
                ((uint64_t) (buf[1]) << 8 * 1) |
                ((uint64_t) (buf[2]) << 8 * 2) |
                ((uint64_t) (buf[3]) << 8 * 3) |
                ((uint64_t) (buf[4]) << 8 * 4) |
                ((uint64_t) (buf[5]) << 8 * 5) |
                ((uint64_t) (buf[6]) << 8 * 6) |

                ((uint64_t) (buf[7]) << 8 * 7);

        ctx->s[ctx->wordIndex] ^= t;
        if (++ctx->wordIndex == (SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx->capacityWords))) {
            keccakf(ctx->s);
            ctx->wordIndex = 0;
        }
    }

    while (tail--) {
        ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
    }
}

static void const* sha3_Finalize(void *priv) {
    sha3_context *ctx = (sha3_context *) priv;

    uint64_t t;

    if( ctx->capacityWords & SHA3_USE_KECCAK_FLAG ) {
        t = (uint64_t)(((uint64_t) 1) << (ctx->byteIndex * 8));
    }
    else {
        t = (uint64_t)(((uint64_t)(0x02 | (1 << 2))) << ((ctx->byteIndex) * 8));
    }

    ctx->s[ctx->wordIndex] ^= ctx->saved ^ t;

    ctx->s[SHA3_KECCAK_SPONGE_WORDS - SHA3_CW(ctx->capacityWords) - 1] ^= SHA3_CONST(0x8000000000000000UL);
    keccakf(ctx->s);

    {
        unsigned i;
        for(i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) {
            const unsigned t1 = (uint32_t) ctx->s[i];
            const unsigned t2 = (uint32_t) ((ctx->s[i] >> 16) >> 16);
            ctx->sb[i * 8 + 0] = (uint8_t) (t1);
            ctx->sb[i * 8 + 1] = (uint8_t) (t1 >> 8);
            ctx->sb[i * 8 + 2] = (uint8_t) (t1 >> 16);
            ctx->sb[i * 8 + 3] = (uint8_t) (t1 >> 24);
            ctx->sb[i * 8 + 4] = (uint8_t) (t2);
            ctx->sb[i * 8 + 5] = (uint8_t) (t2 >> 8);
            ctx->sb[i * 8 + 6] = (uint8_t) (t2 >> 16);
            ctx->sb[i * 8 + 7] = (uint8_t) (t2 >> 24);
        }
    }

    return (ctx->sb);
}

static sha3_return_t sha3_HashBuffer( unsigned bitSize, enum SHA3_FLAGS flags, const void *in, unsigned inBytes, void *out, unsigned outBytes ) {
    sha3_return_t err;
    sha3_context c;

    err = sha3_Init(&c, bitSize);

    if( err != SHA3_RETURN_OK ) {
        return err;
    }

    if( sha3_SetFlags(&c, flags) != flags ) {
        return SHA3_RETURN_BAD_PARAMS;
    }

    sha3_Update(&c, in, inBytes);
    const void *h = sha3_Finalize(&c);

    if (outBytes > bitSize / 8) {
        outBytes = bitSize / 8;
    }

    memcpy(out, h, outBytes);
    return SHA3_RETURN_OK;
}

//------------------------------------------------------------------------------
// This is free and unencumbered software released into the public domain
// https://github.com/kokke/tiny-AES-c
//------------------------------------------------------------------------------
#define CTR             1
#define AES256          1
#define AES_BLOCKLEN    16
#define AES_KEYLEN      32
#define AES_keyExpSize 240
#define Nb               4
#define Nk               8
#define Nr              14

struct AES_ctx {
    uint8_t RoundKey[AES_keyExpSize];
    uint8_t Iv[AES_BLOCKLEN];
};

typedef uint8_t state_t[4][4];

static const uint8_t sbox[256] = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

#define getSBoxValue(num) (sbox[(num)])

static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key) {
    unsigned i, j, k;
    uint8_t tempa[4];

    for (i = 0; i < Nk; ++i) {
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    for (i = Nk; i < Nb * (Nr + 1); ++i) {
        {
            k = (i - 1) * 4;
            tempa[0]=RoundKey[k + 0];
            tempa[1]=RoundKey[k + 1];
            tempa[2]=RoundKey[k + 2];
            tempa[3]=RoundKey[k + 3];

        }

        if (i % Nk == 0) {

            {
                const uint8_t u8tmp = tempa[0];
                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = u8tmp;
            }


            {
                tempa[0] = getSBoxValue(tempa[0]);
                tempa[1] = getSBoxValue(tempa[1]);
                tempa[2] = getSBoxValue(tempa[2]);
                tempa[3] = getSBoxValue(tempa[3]);
            }

            tempa[0] = tempa[0] ^ Rcon[i/Nk];
        }

        if (i % Nk == 4) {
            {
                tempa[0] = getSBoxValue(tempa[0]);
                tempa[1] = getSBoxValue(tempa[1]);
                tempa[2] = getSBoxValue(tempa[2]);
                tempa[3] = getSBoxValue(tempa[3]);
            }
        }

        j = i * 4; k=(i - Nk) * 4;
        RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
    }
}

static void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv) {
    KeyExpansion(ctx->RoundKey, key);
    memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}

static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey) {
    uint8_t i,j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
        }
    }
}

static void SubBytes(state_t* state) {
    uint8_t i, j;

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*state)[j][i] = getSBoxValue((*state)[j][i]);
        }
    }
}

static void ShiftRows(state_t* state) {
    uint8_t temp;

    temp           = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x) {
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

static void MixColumns(state_t* state) {
    uint8_t i;
    uint8_t Tmp, Tm, t;

    for (i = 0; i < 4; ++i) {
        t   = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
        Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
    }
}

static void Cipher(state_t* state, const uint8_t* RoundKey) {
    uint8_t round = 0;

    AddRoundKey(0, state, RoundKey);

    for (round = 1; ; ++round) {
        SubBytes(state);
        ShiftRows(state);

        if (round == Nr) {
            break;
        }

        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }

    AddRoundKey(Nr, state, RoundKey);
}

static void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length) {
    uint8_t buffer[AES_BLOCKLEN];

    unsigned i;
    int bi;

    for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi) {
        if (bi == AES_BLOCKLEN) {
            memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
            Cipher((state_t*)buffer,ctx->RoundKey);

            for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi) {
                if (ctx->Iv[bi] == 255) {
                    ctx->Iv[bi] = 0;
                    continue;
                }

                ctx->Iv[bi] += 1;
                break;
            }

            bi = 0;
        }

        buf[i] = (buf[i] ^ buffer[bi]);
    }
}

//------------------------------------------------------------------------------
// Code in public domain by gnuwimp
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
static uint32_t _aes_adler32(const char* in, uint64_t in_size) {
    uint32_t a = 1;
    uint32_t b = 0;
    unsigned char* c = (unsigned char*) in;

    if (in) {
        for (uint32_t f = 0; f < in_size; ++f) {
            a = (a + c[f]) % 65521;
            b = (b + a) % 65521;
        }
    }

    return (b << 16) | a;
}

//------------------------------------------------------------------------------
static void* _aes_zero_memory(char* in, size_t in_size) {
    #ifdef _WIN32
        RtlSecureZeroMemory(in, in_size);
    #else
        volatile unsigned char* p = (volatile unsigned char*) in;

        while (in_size--) {
            *p = 0;
            p++;
        }
    #endif

    return in;
}

//------------------------------------------------------------------------------
static uint32_t _aes_random_number() {
    uint32_t res = 0;

    #if defined(_WIN32)
        if (rand_s(&res) == 0) {
            return res;
        }
    #elif defined(__linux__)
        if (getrandom(&res, 4, GRND_NONBLOCK) == 4) {
            return res;
        }
    #elif defined(__APPLE__)
        res = arc4random();
        return res;
    #endif

    #ifdef DEBUG
        fprintf(stderr, "warning: no secure random numbers\n");
    #endif

    return rand() * rand();
}

//------------------------------------------------------------------------------
bool sha3_keccak_256(const void* in, int in_size, char* out, int out_size_min32, int iterations) {
    if (in == 0 || in_size < 1 || out == 0 || out_size_min32 < 32 || iterations < 1) {
        return false;
    }
    else {
        uint8_t sha[32];

        memset(out, 0, out_size_min32);

        for (int f = 0; f < iterations; f++) {
            if (f == 0) {
                sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, in, in_size, out, 32);
            }
            else {
                sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, out, 32, sha, 32);
                memcpy(out, sha, 32);
            }
        }

        _aes_zero_memory((char*) sha, 32);
        return true;
    }
}

//------------------------------------------------------------------------------
bool encrypt(const char* in, int in_size, char* out, int out_size, const char* password, int password_iterations) {
    int password_len = (int) strlen(password ? password : "");

    if (in == 0 || in_size < 1 || out == 0 || out_size < in_size + 32 || password_len < 1 || password_iterations < 1) {
        return false;
    }
    else {
        const uint8_t* in_buffer  = (const uint8_t*) in;
        uint8_t*       out_buffer = (uint8_t*) out;
        uint32_t       adler      = _aes_adler32(in, in_size);
        char*          password2  = (char*) calloc(password_len + 20, 1);
        char           salt[12];
        uint8_t        iv[16];
        uint8_t        key1[32];
        uint8_t        key2[32];

        memset(salt, 0, 12);
        memset(iv, 0, 16);

        { // Create salt
            uint32_t* i = (uint32_t*) &salt;
            *i = _aes_random_number();

            i = (uint32_t*) &salt[4];
            *i = _aes_random_number();

            i = (uint32_t*) &salt[8];
            *i = _aes_random_number();
        }

        { // Create iv
            uint32_t* i = (uint32_t*) &iv;
            *i = _aes_random_number();

            i = (uint32_t*) &iv[4];
            *i = _aes_random_number();

            i = (uint32_t*) &iv[8];
            *i = _aes_random_number();

            i = (uint32_t*) &iv[12];
            *i = _aes_random_number();
        }

        { // Create keys
            sha3_keccak_256(password, password_len, (char*) key1, 32, 1);

            memcpy(password2, password, password_len);
            memcpy(password2 + password_len, salt, 12);
            sha3_keccak_256(password2, password_len + 12, (char*) key2, 32, password_iterations);
        }

        { // Copy salt, iv and checksum to buffer, scramble them with first key
            memcpy(out, salt, 12);
            memcpy(out + 12, iv, 16);
            memcpy(out + 12 + 16, &adler, 4);

            for (uint32_t f = 0; f < 32; f++) {
                out_buffer[f] = out_buffer[f] ^ key1[f];
            }
        }

        { // Encrypt bytes with second key that is a hash of password + salt
            struct AES_ctx ctx;

            memcpy(out_buffer + 32, in_buffer, in_size);
            AES_init_ctx_iv(&ctx, key2, iv);
            AES_CTR_xcrypt_buffer(&ctx, out_buffer + 32, in_size);
        }

        _aes_zero_memory((char*) key1, 32);
        _aes_zero_memory((char*) key2, 32);
        _aes_zero_memory(password2, password_len + 12);
        _aes_zero_memory((char*) iv, 16);
        _aes_zero_memory(salt, 12);
        _aes_zero_memory((char*) &adler, 4);
        free(password2);

        return true;
    }
}

//------------------------------------------------------------------------------
bool decrypt(const char* in, int in_size, char* out, int out_size, const char* password, int password_iterations) {
    int password_len = (int) strlen(password ? password : "");

    if (in == 0 || in_size < 33 || out == 0 || out_size < in_size - 32 || password_len < 1 || password_iterations < 1) {
        return false;
    }
    else {
        bool           res        = false;
        const uint8_t* in_buffer  = (const uint8_t*) in;
        uint8_t*       out_buffer = (uint8_t*) out;
        char*          password2  = (char*) calloc(password_len + 20, 1);
        char           salt[12];
        uint8_t        header[32];
        uint8_t        iv[16];
        uint8_t        key1[32];
        uint8_t        key2[32];
        uint32_t       adler1;
        uint32_t       adler2;

        memset(salt, 0, 12);
        memset(iv, 0, 16);

        { // Create key 1 and descramble header
            sha3_keccak_256(password, password_len, (char*) key1, 32, 1);
            memcpy(header, in, 32);

            for (uint32_t f = 0; f < 32; f++) {
                header[f] = header[f] ^ key1[f];
            }
        }

        { // Copy salt, iv and adler from header
            memcpy(salt, header, 12);
            memcpy(iv, header + 12, 16);
            memcpy(&adler1, header + 12 + 16, 4);
        }

        { // Create key 2
            memcpy(password2, password, password_len);
            memcpy(password2 + password_len, salt, 12);
            sha3_keccak_256(password2, password_len + 12, (char*) key2, 32, password_iterations);
        }

        { // Decrypt bytes
            struct AES_ctx ctx;

            memcpy(out_buffer, in_buffer + 32, in_size - 32);
            AES_init_ctx_iv(&ctx, key2, iv);
            AES_CTR_xcrypt_buffer(&ctx, out_buffer, in_size - 32);
        }

        { // Create checksum and compare it with stored checksum
            adler2 = _aes_adler32(out, in_size - 32);
            res    = adler1 == adler2;
        }

        _aes_zero_memory((char*) key1, 32);
        _aes_zero_memory((char*) key2, 32);
        _aes_zero_memory(password2, password_len + 12);
        _aes_zero_memory((char*) iv, 16);
        _aes_zero_memory(salt, 12);
        _aes_zero_memory((char*) &adler1, 4);
        _aes_zero_memory((char*) &adler2, 4);
        free(password2);

        return res;
    }
}

