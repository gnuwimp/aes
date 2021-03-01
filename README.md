# AES

This is an aes encryption/decryption code in one source file.<br>
It uses tiny-AES from https://github.com/kokke/tiny-AES-c.<br>
And sha3 from https://github.com/brainhub/SHA3IUF.<br>
It is untested so use it at your own risk!

### Usage
It uses AES CTR mode for encryption.<br>
And Sha3-256-Keccac for the key hash.<br>
```
const char* PASSWORD = "abc";
const char* TEXT = "Hello World";
const int TEXT_LENGTH = strlen(TEXT) + 1;
char enc[100];
char dec[100];

encrypt(TEXT, TEXT_LENGTH, enc, TEXT_LENGTH + 32, PASSWORD, 1);
decrypt(enc, TEXT_LENGTH + 32, dec, TEXT_LENGTH, PASSWORD, 1);
printf("Input text is <%s>, decrypted text is <%s>\n", TEXT, dec);
```

If you include the cpp file on windows you have to include it first.<br>
Or include the following first:
```
#if defined(_WIN32)
    #define _CRT_RAND_S
    #include <Shlobj.h>
#endif
```

### License
The source is in the public domain.
