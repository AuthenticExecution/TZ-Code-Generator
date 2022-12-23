#include <crypto.h>

#include <spongent.h>

#define NONCE_SIZE 12

struct aes_cipher {
	TEE_OperationHandle op_handle;	/* AES ciphering operation */
	TEE_ObjectHandle key_handle;	/* transient object to load the key */
};

TEE_Result encrypt_aes(
    const unsigned char *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *plaintext,
    unsigned int plaintext_len,
    unsigned char *ciphertext,
    unsigned char *tag
);
TEE_Result decrypt_aes(
    const unsigned char *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *ciphertext,
    unsigned int ciphertext_len,
    unsigned char *plaintext,
    const unsigned char *expected_tag
);
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

TEE_Result encrypt_generic(
    EncryptionType type,
    const unsigned char *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *plaintext,
    unsigned int plaintext_len,
    unsigned char *ciphertext,
    unsigned char *tag
) {
    switch(type) {
        case EncryptionType_Aes:
            return encrypt_aes(
                key,
                ad,
                ad_len,
                plaintext,
                plaintext_len,
                ciphertext,
                tag
            );
        case EncryptionType_Spongent:
            return SpongentWrap(
                key,
                ad,
                ad_len * 8,
                plaintext,
                plaintext_len * 8,
                ciphertext,
                tag,
                0
            );
        default:
            break;
    }

    EMSG("Invalid encryption type: %d", type);
    return 0;
}

TEE_Result decrypt_generic(
    EncryptionType type,
    const unsigned char *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *ciphertext,
    unsigned int ciphertext_len,
    unsigned char *plaintext,
    const unsigned char *expected_tag
) {
    switch(type) {
        case EncryptionType_Aes:
            return decrypt_aes(
                key,
                ad,
                ad_len,
                ciphertext,
                ciphertext_len,
                plaintext,
                expected_tag
            );
        case EncryptionType_Spongent:
            return SpongentUnwrap(
                key,
                ad,
                ad_len * 8,
                ciphertext,
                ciphertext_len * 8,
                plaintext,
                expected_tag
            );
        default:
            break;
    }

    EMSG("Invalid encryption type: %d", type);
    return 0;
}

/* AES-related stuff */
TEE_Result encrypt_aes(
    const unsigned char *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *plaintext,
    unsigned int plaintext_len,
    unsigned char *ciphertext,
    unsigned char *tag
) {
    TEE_Result res;
	struct aes_cipher sess;

    // here we use a zero nonce because we assume nonce is inside associated data
    const unsigned char nonce[NONCE_SIZE] = { 0 };
    unsigned int cipher_len = plaintext_len, tag_len = SECURITY_BYTES;

    if(
        (res = alloc_resources(&sess, TEE_MODE_ENCRYPT)) != TEE_SUCCESS ||
        (res = set_aes_key(&sess, key)) != TEE_SUCCESS ||
        (res = reset_aes_iv(&sess, ad, ad_len, nonce, NONCE_SIZE, plaintext_len)) != TEE_SUCCESS
    ) {
        clean_session(&sess);
        return res;
    }

    res = TEE_AEEncryptFinal(
        sess.op_handle,
        plaintext,
        plaintext_len,
        ciphertext,
        &cipher_len,
        tag,
        &tag_len
    );

    clean_session(&sess);

    if(res != TEE_SUCCESS) {
        EMSG("AES encryption failed: %x", res);
        return res;
    }

    if(cipher_len != plaintext_len) {
        EMSG("Ciphertext size differs from plaintext: %d/%d", plaintext_len, cipher_len);
        return TEE_ERROR_GENERIC;
    }

    if(tag_len != SECURITY_BYTES) {
        EMSG("Tag size differs from expected: %d/%d", tag_len, SECURITY_BYTES);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result decrypt_aes(
    const unsigned char *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *ciphertext,
    unsigned int ciphertext_len,
    unsigned char *plaintext,
    const unsigned char *expected_tag
) {
    TEE_Result res;
	struct aes_cipher sess;

    // here we use a zero nonce because we assume nonce is inside associated data
    const unsigned char nonce[NONCE_SIZE] = { 0 };
    unsigned int plaintext_len = ciphertext_len;

    if(
        (res = alloc_resources(&sess, TEE_MODE_DECRYPT)) != TEE_SUCCESS ||
        (res = set_aes_key(&sess, key)) != TEE_SUCCESS ||
        (res = reset_aes_iv(&sess, ad, ad_len, nonce, NONCE_SIZE, ciphertext_len)) != TEE_SUCCESS
    ) {
        clean_session(&sess);
        return res;
    }

	// copy tag locally (otherwise decrypt would fail)
    unsigned char tag[SECURITY_BYTES];
	TEE_MemMove(tag, expected_tag, SECURITY_BYTES);

    res = TEE_AEDecryptFinal(
        sess.op_handle,
        ciphertext,
        ciphertext_len,
        plaintext,
        &plaintext_len,
        tag,
        SECURITY_BYTES
    );

    clean_session(&sess);

    if(res != TEE_SUCCESS) {
        EMSG("AES decryption failed: %x", res);
        return res;
    }

    if(ciphertext_len != plaintext_len) {
        EMSG("Plaintext size differs from ciphertext: %d/%d", ciphertext_len, plaintext_len);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

void clean_session(struct aes_cipher *sess) {
	if (sess->op_handle != TEE_HANDLE_NULL) {
		TEE_FreeOperation(sess->op_handle);
        sess->op_handle = TEE_HANDLE_NULL;
    }

    if (sess->key_handle != TEE_HANDLE_NULL) {
		TEE_FreeTransientObject(sess->key_handle);
        sess->key_handle = TEE_HANDLE_NULL;
    }
}

TEE_Result alloc_resources(struct aes_cipher *sess, uint32_t mode) {
	TEE_Attribute attr;
	TEE_Result res;

    // initialize struct
    sess->op_handle = TEE_HANDLE_NULL;
    sess->key_handle = TEE_HANDLE_NULL;

	/* Allocate operation: AES/CTR, mode and size from params */
	res = TEE_AllocateOperation(
        &sess->op_handle,
		TEE_ALG_AES_GCM,
		mode, // either TEE_MODE_ENCRYPT or TEE_MODE_DECRYPT
		SECURITY_BYTES * 8
    );

	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation");
		return res;
	}

	/* Allocate transient object according to target key size */
	res = TEE_AllocateTransientObject(
        TEE_TYPE_AES,
		SECURITY_BYTES * 8,
		&sess->key_handle
    );

	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object");
		return res;
	}

    unsigned char key[SECURITY_BYTES] = {0};
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, &key, SECURITY_BYTES);

	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
        return res;
	}

	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
        return res;
	}

	return TEE_SUCCESS;
}

TEE_Result set_aes_key(struct aes_cipher *sess, const unsigned char *key) {
	TEE_Attribute attr;
	TEE_Result res;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, SECURITY_BYTES);
	TEE_ResetTransientObject(sess->key_handle);

	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		return res;
	}

	TEE_ResetOperation(sess->op_handle);
	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
		return res;
	}

	return TEE_SUCCESS;
}

TEE_Result reset_aes_iv(
    struct aes_cipher *sess,
    const unsigned char *aad,
    size_t aad_sz,
    const unsigned char *nonce,
    size_t nonce_sz,
    size_t payload_sz
){
    TEE_Result res = TEE_AEInit(
        sess->op_handle,
        nonce,
        nonce_sz,
        SECURITY_BYTES * 8, // in bits
        aad_sz,
		payload_sz
    );

    if (res != TEE_SUCCESS) {
		EMSG("TEE_AEInit failed %x", res);
		return res;
	}

	TEE_AEUpdateAAD(sess->op_handle, aad, aad_sz);
	return TEE_SUCCESS;
}