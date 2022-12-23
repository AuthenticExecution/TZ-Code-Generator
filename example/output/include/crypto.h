#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <tee_internal_api.h>

#define SECURITY_BYTES 16

typedef enum {
    EncryptionType_Aes, // aes-gcm-128
    EncryptionType_Spongent // spongent-128
} EncryptionType;

TEE_Result encrypt_generic(
    EncryptionType type,
    const unsigned char *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *plaintext,
    unsigned int plaintext_len,
    unsigned char *ciphertext,
    unsigned char *tag
);

TEE_Result decrypt_generic(
    EncryptionType type,
    const unsigned char *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *ciphertext,
    unsigned int ciphertext_len,
    unsigned char *plaintext,
    const unsigned char *expected_tag
);

#endif