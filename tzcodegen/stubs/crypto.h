#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <tee_internal_api.h>
#include <stdint.h>

#define SECURITY_BYTES 16
#define NONCE_SIZE 12

typedef enum {
    EncryptionType_Aes,
    EncryptionType_Spongent
} EncryptionType;

struct aes_cipher {
	uint32_t algo;			/* AES flavour */
	uint32_t mode;			/* Encode or decode */
	uint32_t key_size;		/* AES key size in byte */
	TEE_OperationHandle op_handle;	/* AES ciphering operation */
	TEE_ObjectHandle key_handle;	/* transient object to load the key */
};

void clean_session(struct aes_cipher *sess);
TEE_Result alloc_resources(struct aes_cipher *sess, uint32_t mode);
TEE_Result set_aes_key(struct aes_cipher *sess, const unsigned char *key);
TEE_Result reset_aes_iv(
    struct aes_cipher *sess,
    const unsigned char *aad,
    size_t aad_sz,
    const unsigned char *nonce,
    size_t nonce_sz,
    size_t payload_sz
);

int encrypt(
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

int decrypt(
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

int encrypt_aes(
    void *session,
    const unsigned char *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *plaintext,
    unsigned int plaintext_len,
    unsigned char *ciphertext,
    unsigned char *tag
);

int decrypt_aes(
    void *session,
    const unsigned char *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *ciphertext,
    unsigned int ciphertext_len,
    unsigned char *plaintext,
    const unsigned char *expected_tag
);


#endif