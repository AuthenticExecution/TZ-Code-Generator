#include <crypto.h>

#include <spongent.h>

#define NONCE_SIZE 12

TEE_Result encrypt_aes(
    key_t *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *plaintext,
    unsigned int plaintext_len,
    unsigned char *ciphertext,
    unsigned char *tag
);
TEE_Result decrypt_aes(
    key_t *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *ciphertext,
    unsigned int ciphertext_len,
    unsigned char *plaintext,
    const unsigned char *expected_tag
);
TEE_Result reset_operation(
    TEE_OperationHandle op_handle,
    const unsigned char *aad,
    size_t aad_sz,
    const unsigned char *nonce,
    size_t nonce_sz,
    size_t payload_sz
);
TEE_Result init_aes_key(
    key_t *key_struct
);

TEE_Result init_key(
    EncryptionType type,
    key_t *key
) {
    switch(type) {
        case EncryptionType_Aes:
            return init_aes_key(key);
        case EncryptionType_Spongent:
            key->encrypt_handle = TEE_HANDLE_NULL;
            key->decrypt_handle = TEE_HANDLE_NULL;
            key->key_handle = TEE_HANDLE_NULL;
            return TEE_SUCCESS;
        default:
            break;
    }

    EMSG("Invalid encryption type: %d", type);
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result encrypt_generic(
    EncryptionType type,
    key_t *key,
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
                key->key,
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
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result decrypt_generic(
    EncryptionType type,
    key_t *key,
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
                key->key,
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
    return TEE_ERROR_NOT_SUPPORTED;
}

/* AES-related stuff */
TEE_Result encrypt_aes(
    key_t *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *plaintext,
    unsigned int plaintext_len,
    unsigned char *ciphertext,
    unsigned char *tag
) {
    TEE_Result res;

    // here we use a zero nonce because we assume nonce is inside associated data
    const unsigned char nonce[NONCE_SIZE] = { 0 };
    unsigned int cipher_len = plaintext_len, tag_len = SECURITY_BYTES;

    if(
        (res = reset_operation(
            key->encrypt_handle,
            ad,
            ad_len,
            nonce,
            NONCE_SIZE,
            plaintext_len)
        ) != TEE_SUCCESS
    ) {
        return res;
    }

    res = TEE_AEEncryptFinal(
        key->encrypt_handle,
        plaintext,
        plaintext_len,
        ciphertext,
        &cipher_len,
        tag,
        &tag_len
    );

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
    key_t *key,
    const unsigned char *ad,
    unsigned int ad_len,
    const unsigned char *ciphertext,
    unsigned int ciphertext_len,
    unsigned char *plaintext,
    const unsigned char *expected_tag
) {
    TEE_Result res;

    // here we use a zero nonce because we assume nonce is inside associated data
    const unsigned char nonce[NONCE_SIZE] = { 0 };
    unsigned int plaintext_len = ciphertext_len;

    if(
        (res = reset_operation(
            key->decrypt_handle,
            ad,
            ad_len,
            nonce,
            NONCE_SIZE,
            plaintext_len)
        ) != TEE_SUCCESS
    ) {
        return res;
    }

	// copy tag locally (otherwise decrypt would fail)
    unsigned char tag[SECURITY_BYTES];
	TEE_MemMove(tag, expected_tag, SECURITY_BYTES);

    res = TEE_AEDecryptFinal(
        key->decrypt_handle,
        ciphertext,
        ciphertext_len,
        plaintext,
        &plaintext_len,
        tag,
        SECURITY_BYTES
    );

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

TEE_Result reset_operation(
    TEE_OperationHandle op_handle,
    const unsigned char *aad,
    size_t aad_sz,
    const unsigned char *nonce,
    size_t nonce_sz,
    size_t payload_sz
) {
    TEE_ResetOperation(op_handle);

    TEE_Result res = TEE_AEInit(
        op_handle,
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

	TEE_AEUpdateAAD(op_handle, aad, aad_sz);
	return TEE_SUCCESS;
}

TEE_Result init_aes_key(
    key_t *key
) {
	TEE_Result res;
	TEE_Attribute attr;

	/* Allocate operations */
	res = TEE_AllocateOperation(
        &key->encrypt_handle,
		TEE_ALG_AES_GCM,
		TEE_MODE_ENCRYPT,
		SECURITY_BYTES * 8
    );

	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate encrypt operation");
		return res;
	}

    res = TEE_AllocateOperation(
        &key->decrypt_handle,
		TEE_ALG_AES_GCM,
		TEE_MODE_DECRYPT,
		SECURITY_BYTES * 8
    );

	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate decrypt operation");
		return res;
	}

	/* Allocate transient object according to target key size */
	res = TEE_AllocateTransientObject(
        TEE_TYPE_AES,
		SECURITY_BYTES * 8,
		&key->key_handle
    );

	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object");
		return res;
	}

    /* initialize transient object */
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key->key, SECURITY_BYTES);

	res = TEE_PopulateTransientObject(key->key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		return res;
	}

	res = TEE_SetOperationKey(key->encrypt_handle, key->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey encrypt_handle failed %x", res);
		return res;
	}

    res = TEE_SetOperationKey(key->decrypt_handle, key->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey decrypt_handle failed %x", res);
		return res;
	}

	return TEE_SUCCESS;
}