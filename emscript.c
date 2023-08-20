#include <stdio.h> // for printing and string operations
#include <emscripten.h> // for WASM integration
#include "lib/tomcrypt.h" // for crypto
#include <time.h> // for seeding random function
#include <stdlib.h> // for malloc
extern const ltc_math_descriptor ltm_desc;

//#define MIN(a,b) (((a)<(b))?(a):(b))
//#define MAX(a,b) (((a)>(b))?(a):(b))

// 32-47, 58-64, 91-96, 123-126 specials
// 48-57 nums
// 65-90 uppers
// 97-122 lowers

EMSCRIPTEN_KEEPALIVE
int passwordStrength(char* input, int len) {
    int security = -1;
    int state = -1;
    int prev = -1;
    for (int x = 0; x < len; x++) {
        char cur = input[x];
        if (48 <= cur && cur <= 57) { // nums
            state = 0;
        } else if (65 <= cur && cur <= 90) { // uppers
            state = 1;
        } else if (97 <= cur && cur <= 122) { // lowers
            state = 2;
        } else { // special
            state = 3;
        }
        if (prev != state) { // change of state
            security++;
            prev = state;
        }
    }
    security = MAX(security, 0);

    for (int i = 0; i < len - 1; i++) { // sort the password
        for (int j = 0; j < len - i - 1; j++) {
            if (input[j] > input[j + 1]) {
                char temp = input[j];
                input[j] = input[j+1];
                input[j+1] = temp;
            }
        }
    }
    int uniq = 0; // count up unique
    state = 0;
    prev = 0;
    for (int x = 0; x < len; x++) {
        state = input[x];
        if (prev != state) {
            uniq++;
            prev = state;
        }
    }
    security = MIN(security, uniq);

    if (security > 3) { // Apply length scaling
        security += len/5;
    };
    return MIN(security, 10);
}

EMSCRIPTEN_KEEPALIVE
int genKeypair(unsigned char* pub, unsigned long publen, unsigned char* priv, unsigned long privlen) {
    rsa_key key;
    // Code taken from reference manual

    int prng_idx = find_prng("sprng");

    int err = rsa_make_key(NULL, prng_idx, 2048/8, 65537, &key);
    if (err != CRYPT_OK) {
        return 0;
    }

    rsa_export(pub, &publen, PK_PUBLIC, &key);
    rsa_export(priv, &privlen, PK_PRIVATE, &key);

    rsa_free(&key); // tidy up our memory

    return 1;
}

EMSCRIPTEN_KEEPALIVE
int makeIdentToken(unsigned char* d1, int d1len, unsigned char* d2, int d2len, unsigned char* token, int tokenlen) {
    hash_state sha;
    sha256_init(&sha);

    sha256_process(&sha, d1, d1len); // Hash a concatenation of two buffers
    sha256_process(&sha, d2, d2len);

    if (tokenlen < 32) {
        return 0;
    }
    sha256_done(&sha, token);
    return 32;
}

// lower l
// cap I,O
// num 0,1
// num 1

EMSCRIPTEN_KEEPALIVE
int pwSuggest(char* buf, int length, int yesCap, int yesLow, int yesNum, char* extra, int extralen, int unambig) {
    char* letters = malloc((yesCap + yesLow) * 26 + yesNum * 10 + extralen);
    char* end = letters;
    if (yesCap) { // If we are having capitals
        memcpy(end, "ABCDEFGHJKLMNPQRSTUVWXYZ", 24);
        end += 24;
        if (!unambig) {
            memcpy(end, "IO", 2);
            end += 2;
        }
    }
    if (yesLow) { // If we are having lowercase
        memcpy(end, "abcdefghijkmnopqrstuvwxyz", 25);
        end += 25;
        if (!unambig) {
            *end = 'l';
            end++;
        }
    }
    if (yesNum) { // If we are having numbers
        memcpy(end, "23456789", 8);
        end += 8;
        if (!unambig) {
            memcpy(end, "10", 2);
            end += 2;
        }
    }
    memcpy(end, extra, extralen);
    end += extralen;
    int len = end - letters; // Work out how long the alphabet is
    if (len == 0) {
        return 0;
    }

    for (int x = 0; x < length; x++) { // Generate as many characters as needed
        buf[x] = letters[rand() % len];
    }
    return length;
}

EMSCRIPTEN_KEEPALIVE
void setup() {
    // Code from reference manual to make libraries behave correctly
    srand(time(NULL));
    register_prng(&sprng_desc);
    ltc_mp = ltm_desc;
}

EMSCRIPTEN_KEEPALIVE
int encryptPW(unsigned char* buf, unsigned long buflen, unsigned char* key, unsigned int keylen, unsigned char* pw, unsigned int pwlen) {
    rsa_key rsa;
    // Some code taken from reference manual here
    if (rsa_import(key, keylen, &rsa)) { // Try to import key from buffer
        return 0;
    }
    int prng_idx = find_prng("sprng");

    rsa_encrypt_key_ex(pw, pwlen, buf, &buflen, NULL, 0, NULL, prng_idx, 0, LTC_PKCS_1_V1_5, &rsa);
    return 1; // Indicate success
}

EMSCRIPTEN_KEEPALIVE
int decryptPW(unsigned char* buf, unsigned long buflen, unsigned char* key, unsigned int keylen, unsigned char* epw, unsigned long epwlen) {
    rsa_key rsa;
    // Some code taken from reference manual here
    if (rsa_import(key, keylen, &rsa)) { // Try to import key from buffer
        return 0;
    }

    int status;
    rsa_decrypt_key_ex(epw, epwlen, buf, &buflen, NULL, 0, 0, LTC_PKCS_1_V1_5, &status, &rsa);
    return status; // Indicate status
}