#include <crypto.h>

#include <spongent.h>

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
) {
    switch(type) {
        case EncryptionType_Aes:
            return encrypt_aes(
                session,
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
            EMSG("Invalid encryption type: %d", type);
            return 0;
    }
}

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
) {
    switch(type) {
        case EncryptionType_Aes:
            return decrypt_aes(
                session,
                key,
                ad,
                ad_len,
                ciphertext,
                ciphertext_len,
                plaintext,
                (unsigned char *) expected_tag
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
            EMSG("Invalid encryption type: %d", type);
            return 0;
    }
}

/* AES-related stuff */
int encrypt_aes(
    void *session,
    const unsigned char *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *plaintext,
    unsigned int plaintext_len,
    unsigned char *ciphertext,
    unsigned char *tag
) {
    /* Get ciphering context from session ID */
	struct aes_cipher *sess = (struct aes_cipher *) session;

    // here we use a zero nonce because we assume nonce is inside associated data
    const unsigned char nonce[NONCE_SIZE] = { 0 };
    unsigned int cipher_len, tag_len;

    if(
        alloc_resources(sess, TEE_MODE_ENCRYPT) != TEE_SUCCESS ||
        set_aes_key(sess, key) != TEE_SUCCESS ||
        reset_aes_iv(sess, ad, ad_len, nonce, NONCE_SIZE, plaintext_len) != TEE_SUCCESS
    ) {
        clean_session(sess);
        return 0;
    }

    TEE_Result res = TEE_AEEncryptFinal(
        sess->op_handle,
        plaintext,
        plaintext_len,
        ciphertext,
        &cipher_len,
        tag,
        &tag_len
    );

    clean_session(sess);

    if(res != TEE_SUCCESS) {
        EMSG("AES encryption failed: %d", res);
        return 0;
    }

    if(cipher_len != plaintext_len) {
        EMSG("Ciphertext size differs from plaintext: %d/%d", plaintext_len, cipher_len);
        return 0;
    }

    if(tag_len != SECURITY_BYTES) {
        EMSG("Tag size differs from expected: %d/%d", tag_len, SECURITY_BYTES);
        return 0;
    }

    return 1;
}

int decrypt_aes(
    void *session,
    const unsigned char *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *ciphertext,
    unsigned int ciphertext_len,
    unsigned char *plaintext,
    const unsigned char *expected_tag
) {
    /* Get ciphering context from session ID */
	struct aes_cipher *sess = (struct aes_cipher *) session;

    // here we use a zero nonce because we assume nonce is inside associated data
    const unsigned char nonce[NONCE_SIZE] = { 0 };
    unsigned int plaintext_len;

    DMSG("Allocating resources..");

    if(
        alloc_resources(sess, TEE_MODE_DECRYPT) != TEE_SUCCESS ||
        set_aes_key(sess, key) != TEE_SUCCESS ||
        reset_aes_iv(sess, ad, ad_len, nonce, NONCE_SIZE, ciphertext_len) != TEE_SUCCESS
    ) {
        clean_session(sess);
        return 0;
    }

    DMSG("Decrypting..");

    TEE_Result res = TEE_AEDecryptFinal(
        sess->op_handle,
        ciphertext,
        ciphertext_len,
        plaintext,
        &plaintext_len,
        expected_tag,
        SECURITY_BYTES
    );

    DMSG("Cleaning session..");
    clean_session(sess);

    if(res != TEE_SUCCESS) {
        EMSG("AES decryption failed: %d", res);
        return 0;
    }

    if(ciphertext_len != plaintext_len) {
        EMSG("Plaintext size differs from ciphertext: %d/%d", ciphertext_len, plaintext_len);
        return 0;
    }

    return 1;
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

    // for starters, clean up session
    clean_session(sess);

    sess->algo = TEE_ALG_AES_GCM;
    sess->key_size = SECURITY_BYTES;
    sess->mode = mode; // either TEE_MODE_ENCRYPT or TEE_MODE_DECRYPT

	/* Allocate operation: AES/CTR, mode and size from params */
	res = TEE_AllocateOperation(
        &sess->op_handle,
		sess->algo,
		sess->mode,
		sess->key_size * 8
    );

	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation");
		clean_session(sess);
		return res;
	}

	/* Allocate transient object according to target key size */
	res = TEE_AllocateTransientObject(
        TEE_TYPE_AES,
		sess->key_size * 8,
		&sess->key_handle
    );

	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object");
		clean_session(sess);
		return res;
	}

    unsigned char key[SECURITY_BYTES] = {0};
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, &key, SECURITY_BYTES);

	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
        clean_session(sess);
        return res;
	}

	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
        clean_session(sess);
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
        clean_session(sess);
		return res;
	}

	TEE_ResetOperation(sess->op_handle);
	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
        clean_session(sess);
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
        SECURITY_BYTES,
        aad_sz,
		payload_sz
    );

    if (res != TEE_SUCCESS) {
		EMSG("TEE_AEInit failed %x", res);
        clean_session(sess);
		return res;
	}

	TEE_AEUpdateAAD(sess->op_handle, aad, aad_sz);
	return TEE_SUCCESS;
}