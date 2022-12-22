#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <tee_internal_api.h>

#include <authentic_execution.h>
#include <pta_attestation.h>
#include <spongent.h>
#include <crypto.h>
#include <connection.h>

#include {header_file}

#define VENDOR_ID {vendor_id}
#define NUM_INPUTS {num_inputs}
#define NUM_ENTRIES {num_entrys}
#define ENTRY_START_INDEX 4

// I define a new type `input_t` for input functions
typedef void (*input_t)(void *, uint32_t, TEE_Param *, unsigned char *, uint32_t);
typedef void (*entry_t)(void *, uint32_t, TEE_Param *, unsigned char *, uint32_t);

// this is the array that will contain the inputs
input_t input_funcs[NUM_INPUTS] = { {fill_inputs} };
entry_t entry_funcs[NUM_ENTRIES] = { {fill_entrys} };
// ------------------------------------------------------

static const TEE_UUID pta_attestation_uuid = ATTESTATION_UUID;

int total_node = 0; // WTF is this?!
unsigned char module_key[16] = { 0 };

//TODO check expected parameter types

static TEE_Result set_key(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	const unsigned int ad_len = 7;
	const uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_NONE
	);
    Connection connection;

	// sanity checks
	if(
		param_types != exp_param_types ||
		params[0].memref.size != ad_len ||
		params[1].memref.size != SECURITY_BYTES || 
		params[2].memref.size != SECURITY_BYTES
	) {
		EMSG(
			"Bad inputs: %d/%d %d %d %d",
			param_types,
			exp_param_types,
			params[0].memref.size,
			params[1].memref.size,
			params[2].memref.size
		);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// copy tag locally (otherwise decrypt would not work)
	unsigned char expected_tag[SECURITY_BYTES];
	TEE_MemMove(expected_tag, params[2].memref.buffer, SECURITY_BYTES);

	DMSG("Decrypting payload..");
	int decrypt_res = decrypt_generic(
		session,
		EncryptionType_Aes,
		module_key,
		params[0].memref.buffer,
		params[0].memref.size,
		params[1].memref.buffer,
		params[1].memref.size,
		connection.connection_key,
		expected_tag
	);

	if (!decrypt_res) {
		return TEE_ERROR_SIGNATURE_INVALID;
	}

	DMSG("Payload decrypted");

	const unsigned char *ad = params[0].memref.buffer;
	connection.encryption = ad[0];
	connection.conn_id = (ad[1] << 8) | ad[2];
	connection.io_id = (ad[3] << 8) | ad[4];
	connection.nonce = 0;

	DMSG("Adding connection");

	// replace if existing
	if(!connections_replace(&connection)) {
		total_node = total_node + 1; //TODO remove this shit
		connections_add(&connection);
	}

	return TEE_SUCCESS;
}

static TEE_Result disable(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	DMSG("Disabling module");
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	const uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;
    Connection connection;

	sess = (struct aes_cipher *)session;
    char nonce[12] = { 0 };
    size_t nonce_sz = 12;

    alloc_resources(sess, TEE_MODE_DECRYPT);
    set_aes_key(sess, module_key);
    reset_aes_iv(sess, params[0].memref.buffer, params[0].memref.size, nonce, nonce_sz, params[1].memref.size);

    char *tag;
    tag = params[0].memref.buffer;
    char *temp;

    void *decrypted_nonce = NULL;
    void *tag_void = NULL;

   //==========================================
    decrypted_nonce = TEE_Malloc(2, 0);
    tag_void = TEE_Malloc(params[2].memref.size, 0);
	if (!decrypted_nonce || !tag_void)
		goto out;

	TEE_MemMove(tag_void, params[2].memref.buffer, params[2].memref.size);

	res = TEE_AEDecryptFinal(sess->op_handle, params[1].memref.buffer,
				 params[1].memref.size, decrypted_nonce, &params[2].memref.size, 
				 tag_void, params[2].memref.size);

	if (!res) {
		delete_all_connections();
    }

out:
	TEE_Free(decrypted_nonce);
    TEE_Free(tag_void);

	return res;
}

//======================================================================

static TEE_Result attest(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	const uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess;

	sess = (struct aes_cipher *)session;

	// ------------ Call PTA ---------**************************************************
	TEE_TASessionHandle pta_session = TEE_HANDLE_NULL;
	uint32_t ret_origin = 0;
	uint32_t pta_param_types = TEE_PARAM_TYPES( TEE_PARAM_TYPE_MEMREF_INPUT,
											TEE_PARAM_TYPE_MEMREF_OUTPUT, 
											TEE_PARAM_TYPE_NONE,
											TEE_PARAM_TYPE_NONE);

	TEE_Param pta_params[TEE_NUM_PARAMS];

	// prepare the parameters for the pta
	uint16_t vendor_id = VENDOR_ID;
	pta_params[0].memref.buffer = &vendor_id;
	pta_params[0].memref.size = 2;
	pta_params[1].memref.buffer = module_key;
	pta_params[1].memref.size = 16;

	// ------------ Open Session to PTA ---------
	res = TEE_OpenTASession(&pta_attestation_uuid, 0, 0, NULL, &pta_session,
				&ret_origin);

	if (res == TEE_SUCCESS) {
		// ------------ Invoke command at PTA (get_module key) ---------
		res = TEE_InvokeTACommand(pta_session, 0, ATTESTATION_CMD_GET_MODULE_KEY,
										pta_param_types, pta_params, &ret_origin);

		// ------------ Close Session to PTA ---------
		TEE_CloseTASession(pta_session);
	}

	if (res != TEE_SUCCESS)
		return res;

	//TODO remove/change?
	DMSG("Generating response..");
	void *tag = TEE_Malloc(16, 0);

	// encrypt challenge (get the MAC)
	int r = encrypt_generic(
		session,
		EncryptionType_Aes,
		module_key,
		params[0].memref.buffer,
		params[0].memref.size,
		NULL,
		0,
		NULL,
		tag
	);

	DMSG("Response generated");

	if (r) {
		params[1].memref.size = 16;
		TEE_MemMove(params[1].memref.buffer, tag, params[1].memref.size);
    }
    else {
    	DMSG("MAC generation failed: %d", res);
    }

	TEE_Free(tag);

	return res;

}

//======================================================================
void handle_output(void *session, uint32_t output_id, uint32_t param_types,
                   TEE_Param params[4], unsigned char *data_input, uint32_t data_len) {

	unsigned char *data;
	unsigned char *conn_id;
	unsigned char *tag;
	conn_id = malloc(16 * 2);
	data = malloc(16 * 16); /* Maximum number of output*/
	tag = malloc(16 * 16);
    memcpy(data, data_input, data_len);

	struct aes_cipher *sess;
	sess = (struct aes_cipher *)session;

	uint8_t numberOfOutput = 0;
	uint8_t totalOutput = params[0].value.b;
	uint8_t indexOfData = params[0].value.a;

	const void *text = data; // for AES

	BitSequence output[data_len];
	BitSequence tag_spongent[16];
	BitSequence data_spongent[data_len];
	memcpy(data_spongent, data, data_len); // for spongent

	uint8_t index = 0;

	int arr[total_node];
	find_connections(output_id, arr, &numberOfOutput);
	
	for(int i = 0; i < numberOfOutput; i++) {

		Connection* connection = connections_get(arr[i]);
		char nonce[12] = { 0 };
    	size_t nonce_sz = 12;

		unsigned char aad[2] = { 0 };
		int j = 1;
    	for(int m = 0; m < 2; m++){
    		aad[m] = ((connection->nonce) >> (8*j)) & 0xFF; // ########
    		j--;
    	}

		unsigned char conn_id_array[2] = { 0 };
		int c = 1;
    	for(int m = 0; m < 2; m++){
    		conn_id_array[m] = ((connection->conn_id) >> (8*c)) & 0xFF;
    		c--;
    	}
		memcpy(conn_id + (2 * i), conn_id_array, 2); //^^^^^^^^^^^^^^^^^^^^^^^

		//*************** ^ ^ *******************************************************

		if(connection->encryption == AES) {

    		alloc_resources(sess, TEE_MODE_ENCRYPT);
    		set_aes_key(sess, connection->connection_key); 
    		reset_aes_iv(sess, aad, 2, nonce, nonce_sz, data_len);
			
			void *encrypt = NULL;
			void *tag_void = NULL;
			uint32_t sz = 16;

			encrypt = TEE_Malloc(data_len, 0);
			tag_void = TEE_Malloc(16, 0);

			TEE_Result res = TEE_AEEncryptFinal(sess->op_handle, text, data_len,
					encrypt, &data_len, tag_void, &sz);

			if (!res) {
				
				data[index] = data_len & 0xFF;
				memcpy(data + index + 1, encrypt, data_len);//^^^^^^^^^^^^^^^^
				memcpy(tag + (16 * i), tag_void, 16);//^^^^^^^^^^^^^^^^^^^^^
				TEE_Free(encrypt);
    			TEE_Free(tag_void);
			}
		} // if AES 
		else {
			encrypt_generic(
				session,
				EncryptionType_Spongent,
				connection->connection_key,
				aad,
				2,
				data_spongent,
				data_len,
				output,
				tag_spongent
			);
			
			data[index] = data_len & 0xFF;
			memcpy(data + index + 1, output, data_len);//^^^^^^^^^^^^^^^^^^^^^
			memcpy(tag + (16 * i), tag_spongent, 16);//^^^^^^^^^^^^^^^^^^^^^^
		} // if spongent

		index = index + data_len + 1;
		connection->nonce = connection->nonce + 1; //######

    } // for

	TEE_MemMove(params[1].memref.buffer + (totalOutput * 2), conn_id, (2 * numberOfOutput));	
	TEE_MemMove(params[2].memref.buffer + indexOfData, data, ((data_len * numberOfOutput) + numberOfOutput));
	TEE_MemMove(params[3].memref.buffer + (totalOutput * 16), tag, (16 * numberOfOutput));
    //-------------------------------------------------------------------------------
	params[0].value.b = totalOutput + numberOfOutput;
	params[0].value.a = indexOfData + (data_len * numberOfOutput) + numberOfOutput;

	free(data);
	free(conn_id);
	free(tag);
	
}

//=========================================================================

TEE_Result handle_input(void *session, uint32_t param_types, TEE_Param params[4]){

	const uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_MEMREF_INOUT,
				TEE_PARAM_TYPE_MEMREF_INOUT);

	TEE_Result res;
	struct aes_cipher *sess;
	sess = (struct aes_cipher *)session;

	uint32_t size = params[0].value.a;
	unsigned char* data;
	data = malloc(size);

	Connection* connection = connections_get(params[0].value.b);
	if(connection == NULL) return TEE_ERROR_BAD_PARAMETERS;

	char nonce[12] = { 0 };
    size_t nonce_sz = 12;

	unsigned char aad[2] = { 0 };
	int j = 1;
    for(int m = 0; m < 2; m++){
    	aad[m] = ((connection->nonce) >> (8*j)) & 0xFF; // ########
    	j--;
    }

	//---------------------------------------------------------------
	if(connection->encryption == AES){

		alloc_resources(sess, TEE_MODE_DECRYPT);
    	set_aes_key(sess, connection->connection_key); //#######
    	reset_aes_iv(sess, aad, 2, nonce, nonce_sz, size);

    	void *decrypted_data = NULL;
    	void *tag_void = NULL;

    	decrypted_data = TEE_Malloc(size, 0);
    	tag_void = TEE_Malloc(16, 0);

		TEE_MemMove(tag_void, params[3].memref.buffer, 16);

		res = TEE_AEDecryptFinal(sess->op_handle, params[2].memref.buffer, size,
						decrypted_data, &size, tag_void, 16);

		if (!res) {
		
      		memcpy(data, decrypted_data, size);
	  	
	  		TEE_Free(decrypted_data);
	  		TEE_Free(tag_void);
		}
	}// if AES
	else{

		BitSequence tag_spongent[16]; 	// TAG length is the same as the key length. 16 bytes.
		BitSequence encrypted_data[size];

		for (int n = 0; n < size; n++){
			encrypted_data[n] = ((uint8_t *)params[2].memref.buffer)[n];
		}

		for (int n = 0; n < 16; n++){
			tag_spongent[n] = ((uint8_t *)params[3].memref.buffer)[n];
		}

		SpongentUnwrap(connection->connection_key, aad, 16, encrypted_data,
															size * 8, data, tag_spongent);


	}// if spongent

	connection->nonce = connection->nonce + 1;
	params[0].value.a = 0;
	params[0].value.b = 0;
	
	if(connection->io_id >= 0 && connection->io_id < NUM_INPUTS) {
		input_funcs[connection->io_id](session, param_types, params, data, size);
	}
	else{
		DMSG("Not Valid Input Index");
		return TEE_ERROR_OVERFLOW;
	}

	return TEE_SUCCESS;
}
//-----------------------------------------------------------------------
TEE_Result handle_entry(void *session, uint32_t param_types, TEE_Param params[4]){

	const uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_MEMREF_INOUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT);

	unsigned char *data_input;
	data_input = malloc(16 * 16); 
	
	uint32_t size = params[0].value.a;
	uint16_t entry_id = params[0].value.b;

	memcpy(data_input, params[2].memref.buffer, size);

	params[0].value.a = 0;
	params[0].value.b = 0;
	
	if(entry_id - ENTRY_START_INDEX >= 0 && entry_id - ENTRY_START_INDEX < NUM_ENTRIES) {

		entry_funcs[entry_id - ENTRY_START_INDEX](session, param_types, params, data_input, size);
	}
	else{
		DMSG("Not Valid Entry Index");
		return TEE_ERROR_OVERFLOW;
	}

	return TEE_SUCCESS;
}

// Called when the TA is created =======================================
TEE_Result TA_CreateEntryPoint(void) {
   return TEE_SUCCESS;
}

// Called when the TA is destroyed
void TA_DestroyEntryPoint(void) {
}

// open session
TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void __unused **session)
{

	struct aes_cipher *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;

	return TEE_SUCCESS;
}

// close session
void TA_CloseSessionEntryPoint(void *session)
{

	struct aes_cipher *sess;

	/* Get ciphering context from session ID */
	sess = (struct aes_cipher *)session;

	/* Release the session resources */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);
}

// invoke command
TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd, uint32_t param_types,
					TEE_Param params[4])
{
	switch (cmd) {
	case SET_KEY:
		return set_key(session, param_types, params);
	case ATTEST:
		return attest(session, param_types, params);
	case DISABLE:
		return disable(session, param_types, params);
	case HANDLE_INPUT:
		return handle_input(session, param_types, params);
	case ENTRY:
		return handle_entry(session, param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}