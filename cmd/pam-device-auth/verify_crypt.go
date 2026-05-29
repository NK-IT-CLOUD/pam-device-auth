package main

/*
#cgo LDFLAGS: -lcrypt
#include <crypt.h>
#include <string.h>
#include <stdlib.h>

// verify_password uses crypt_r (thread-safe) to check a password against a shadow hash.
// Returns 1 on match, 0 on mismatch, -1 on error.
static int verify_password(const char *password, const char *hash) {
    struct crypt_data data;
    memset(&data, 0, sizeof(data));

    char *result = crypt_r(password, hash, &data);
    if (result == NULL) {
        return -1;
    }

    // Constant-time comparison to prevent timing attacks
    size_t hash_len = strlen(hash);
    size_t result_len = strlen(result);
    if (hash_len != result_len) {
        return 0;
    }

    volatile int diff = 0;
    for (size_t i = 0; i < hash_len; i++) {
        diff |= result[i] ^ hash[i];
    }
    return diff == 0 ? 1 : 0;
}
*/
import "C"

import "unsafe"

// verifyCrypt checks a password against a shadow-style hash using crypt_r(3).
// Uses libxcrypt which supports yescrypt ($y$), SHA-512 ($6$), bcrypt ($2b$), and more.
func verifyCrypt(password, hash string) bool {
	cPassword := C.CString(password)
	cHash := C.CString(hash)
	defer C.free(unsafe.Pointer(cPassword))
	defer C.free(unsafe.Pointer(cHash))

	result := C.verify_password(cPassword, cHash)
	return result == 1
}
