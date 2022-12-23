#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <tee_internal_api.h>
#include <stdint.h>

#define SECURITY_BYTES 16
#define NONCE_SIZE 12

typedef enum {
    EncryptionType_Aes, // aes-gcm-128
    EncryptionType_Spongent // spongent-128
} EncryptionType;

struct aes_cipher {
	uint32_t algo;			/* AES flavour */
	uint32_t mode;			/* Encode or decode */
	uint32_t key_size;		/* AES key size in byte */
	TEE_OperationHandle op_handle;	/* AES ciphering operation */
	TEE_ObjectHandle key_handle;	/* transient object to load the key */
};

TEE_Result encrypt_generic(
    void *session,
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
    void *session,
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