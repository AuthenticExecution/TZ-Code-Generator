#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <authentic_execution.h>
#include <pta_attestation.h>
#include <spongent.h>
#include <crypto.h>
#include <connection.h>

#include {header_file}

#define VENDOR_ID {vendor_id}
#define NUM_INPUTS {num_inputs}
#define NUM_ENTRIES {num_entrys}

input_t input_funcs[NUM_INPUTS] = { {fill_inputs} };
entry_t entry_funcs[NUM_ENTRIES] = { {fill_entrys} };

static const TEE_UUID pta_attestation_uuid = ATTESTATION_UUID;

int total_node = 0; // WTF is this?!
unsigned char module_key[SECURITY_BYTES] = { 0 };
//TODO store current nonce for set_key and disable!!

static TEE_Result retrieve_module_key(void) {
	TEE_TASessionHandle pta_session = TEE_HANDLE_NULL;
	uint32_t ret_origin = 0;
	uint32_t pta_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT, 
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	TEE_Param pta_params[TEE_NUM_PARAMS];
	uint16_t vendor_id = VENDOR_ID;

	// prepare parameters
	pta_params[0].memref.buffer = &vendor_id;
	pta_params[0].memref.size = 2;
	pta_params[1].memref.buffer = module_key;
	pta_params[1].memref.size = SECURITY_BYTES;

	// open session to PTA
	TEE_Result res = TEE_OpenTASession(
		&pta_attestation_uuid,
		0,
		0,
		NULL,
		&pta_session,
		&ret_origin
	);

	if(res != TEE_SUCCESS) {
		return res;
	}

	// call command to retrieve module key
	res = TEE_InvokeTACommand(
		pta_session,
		0,
		ATTESTATION_CMD_GET_MODULE_KEY,
		pta_param_types,
		pta_params,
		&ret_origin
	);

	// close session
	TEE_CloseTASession(pta_session);

	return res;
}

TEE_Result set_key(
	uint32_t param_types,
	TEE_Param params[4]
) {
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
			"Bad inputs: %d/%d %d/%d %d/%d %d/%d",
			param_types,
			exp_param_types,
			params[0].memref.size,
			ad_len,
			params[1].memref.size,
			SECURITY_BYTES,
			params[2].memref.size,
			SECURITY_BYTES
		);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// decrypt data
	TEE_Result res = decrypt_generic(
		EncryptionType_Aes,
		module_key,
		params[0].memref.buffer,
		params[0].memref.size,
		params[1].memref.buffer,
		params[1].memref.size,
		connection.connection_key,
		params[2].memref.buffer
	);

	if (res != TEE_SUCCESS) {
		EMSG("Failed to decrypt data: %x", res);
		return res;
	}

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

TEE_Result disable(
	uint32_t param_types,
	TEE_Param params[4]
) {
	const unsigned int ad_len = 2, cipher_len = 2;
	const uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_NONE
	);

	// sanity checks
	if(
		param_types != exp_param_types ||
		params[0].memref.size != ad_len ||
		params[1].memref.size != cipher_len || 
		params[2].memref.size != SECURITY_BYTES
	) {
		EMSG(
			"Bad inputs: %d/%d %d/%d %d/%d %d/%d",
			param_types,
			exp_param_types,
			params[0].memref.size,
			ad_len,
			params[1].memref.size,
			cipher_len,
			params[2].memref.size,
			SECURITY_BYTES
		);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	unsigned char decrypted_nonce[cipher_len];

	// decrypt data
	TEE_Result res = decrypt_generic(
		EncryptionType_Aes,
		module_key,
		params[0].memref.buffer,
		params[0].memref.size,
		params[1].memref.buffer,
		params[1].memref.size,
		decrypted_nonce,
		params[2].memref.buffer
	);

	if (res != TEE_SUCCESS) {
		EMSG("Failed to decrypt data: %x", res);
		return res;
	}

	// all done: deleting all connections
	DMSG("Deleting all connections");
	delete_all_connections();
	return TEE_SUCCESS;
}

TEE_Result attest(
	uint32_t param_types,
	TEE_Param params[4]
) {
	const uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	// sanity checks
	if(
		param_types != exp_param_types ||
		params[0].memref.size <= 0 ||
		params[1].memref.size != SECURITY_BYTES
	) {
		EMSG(
			"Bad inputs: %d/%d %d %d/%d",
			param_types,
			exp_param_types,
			params[0].memref.size,
			params[1].memref.size,
			SECURITY_BYTES
		);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// calling PTA to retrieve the module key
	DMSG("Retrieving module key from PTA");
	TEE_Result res = retrieve_module_key();
	if(res != TEE_SUCCESS) {
		DMSG("Failed to retrieve module key from PTA");
		return res;
	}

	DMSG("Generating response to the challenge");
	unsigned char tag[SECURITY_BYTES];

	// encrypt challenge to compute MAC
	res = encrypt_generic(
		EncryptionType_Aes,
		module_key,
		params[0].memref.buffer,
		params[0].memref.size,
		NULL,
		0,
		NULL,
		tag
	);

	if(res == TEE_SUCCESS) {
		params[1].memref.size = SECURITY_BYTES;
		TEE_MemMove(params[1].memref.buffer, tag, params[1].memref.size);
    }
    else {
    	EMSG("MAC generation failed: %x", res);
    }

	return res;
}

void handle_output(
	uint32_t output_id, //TODO this should be 16 bits
    TEE_Param params[4],
	unsigned char *data_input,
	uint32_t data_len
) {
	//TODO change this SHIT please
	uint8_t index = 0;
	uint8_t numberOfOutput = 0;
	int arr[total_node];

	DMSG("Handling output ID %d. Data size: %d", output_id, data_len);
	find_connections(output_id, arr, &numberOfOutput);

	uint8_t totalOutput = params[0].value.b;
	uint8_t indexOfData = params[0].value.a;

	// find offsets in output buffers TODO please improve
	//TODO also need checks to ensure we don't overflow these buffers
	unsigned char *conn_id_offset = (unsigned char *) params[1].memref.buffer + 2 * totalOutput;
	unsigned char *payload_offset = (unsigned char *) params[2].memref.buffer + indexOfData;
	unsigned char *tag_offset = (unsigned char *) params[3].memref.buffer + SECURITY_BYTES * totalOutput;

	DMSG("Number of connections found: %d", numberOfOutput);

	// iterate over all connections found for this output and compute payload+MAC
	for(int i = 0; i < numberOfOutput; i++) {
		DMSG("Computing payload for connection %d", arr[i]);

		Connection* conn = connections_get(arr[i]);
		// reverse nonce and conn_id (i.e., convert from little to big endian)
		uint16_t nonce_rev = conn->nonce << 8 | conn->nonce >> 8;
		uint16_t conn_id_rev = conn->conn_id << 8 | conn->conn_id >> 8;

		// add conn_id to buffer
		TEE_MemMove(conn_id_offset + 2 * i, (void *) &conn_id_rev, 2);

		// encrypt payload
		TEE_Result res = encrypt_generic(
			conn->encryption,
			conn->connection_key,
			(void *) &nonce_rev, // nonce is the associated data
			2,
			data_input,
			data_len,
			payload_offset + index + 1,
			tag_offset + SECURITY_BYTES * i
		);

		if(res != TEE_SUCCESS) {
			EMSG(
				"Failed to encrypt payload for connection %d of output %d: %x",
				conn->conn_id,
				output_id,
				res
			);
			return;
		}

		payload_offset[index] = data_len & 0xFF; //TODO what if it's bigger than 8 bits?!!?!?
		index = index + data_len + 1; // why the hell + 1?!
		conn->nonce = conn->nonce + 1;
	}

	//TODO please, please change this
	params[0].value.b = totalOutput + numberOfOutput;
	params[0].value.a = indexOfData + (data_len * numberOfOutput) + numberOfOutput;
	DMSG("handle_output completed");
}

TEE_Result handle_input(
	uint32_t param_types,
	TEE_Param params[4]
) {
	const uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_MEMREF_INOUT
	);

	// sanity checks
	// TODO parametrize max size of buffers, both here and in EM. Check consistency
	if(
		param_types != exp_param_types
	) {
		EMSG(
			"Bad inputs: %d/%d",
			param_types,
			exp_param_types
		);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	unsigned int payload_size = params[0].value.a;
	uint16_t conn_id = params[0].value.b;

	DMSG("Handling input of connection ID: %d", conn_id);

	Connection* conn = connections_get(conn_id);
	if(conn == NULL) {
		EMSG("No connection found with ID %d", conn_id);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// nonce will be used as associated data. Converting from little to big endian
	uint16_t nonce_rev = conn->nonce << 8 | conn->nonce >> 8;

	// allocate memory for decrypted payload
	unsigned char *payload = TEE_Malloc(payload_size, 0);
	if(payload == NULL) {
		EMSG("Failed to allocate payload for input");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	// decrypt data
	TEE_Result res = decrypt_generic(
		conn->encryption,
		conn->connection_key,
		(void *) &nonce_rev,
		2,
		params[2].memref.buffer,
		payload_size,
		payload,
		params[3].memref.buffer
	);

	if (res != TEE_SUCCESS) {
		EMSG("Failed to decrypt data: %x", res);
		TEE_Free(payload);
		return res;
	}

	conn->nonce = conn->nonce + 1;
	// params[0] is used to store data for possible outputs
	params[0].value.a = 0;
	params[0].value.b = 0;
	
	// call input function
	if(conn->io_id < NUM_INPUTS) {
		input_funcs[conn->io_id](
			params,
			payload,
			payload_size
		);
		res = TEE_SUCCESS;
	}
	else{
		DMSG("Input ID not valid: %d/%d", conn->io_id, NUM_INPUTS);
		res = TEE_ERROR_OVERFLOW;
	}

	TEE_Free(payload);
	return res;
}

TEE_Result handle_entry(
	uint32_t param_types,
	TEE_Param params[4]
) {
	const uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT
	);

	// sanity checks
	// TODO parametrize max size of buffers, both here and in EM. Check consistency
	if(
		param_types != exp_param_types
	) {
		EMSG(
			"Bad inputs: %d/%d",
			param_types,
			exp_param_types
		);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	unsigned int payload_size = params[0].value.a;
	uint16_t entry_id = params[0].value.b;

	DMSG("Handling custom entry point with ID: %d", entry_id);

	// copy input payload into a buffer (params[2] will be used for outputs)
	unsigned char *payload = TEE_Malloc(payload_size, 0);
	if(payload == NULL) {
		EMSG("Failed to allocate payload for entry point");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TEE_MemMove(payload, params[2].memref.buffer, payload_size);

	// params[0] is used to store data for possible outputs
	params[0].value.a = 0;
	params[0].value.b = 0;

	// call entry point
	TEE_Result res = TEE_SUCCESS;
	if(
		entry_id - ENTRY_START_INDEX >= 0 &&
		entry_id - ENTRY_START_INDEX < NUM_ENTRIES
	) {
		entry_funcs[entry_id - ENTRY_START_INDEX](
			params,
			payload,
			payload_size
		);
	}
	else{
		DMSG(
			"Entry point ID not valid: %d/%d",
			entry_id - ENTRY_START_INDEX,
			NUM_ENTRIES
		);
		res = TEE_ERROR_OVERFLOW;
	}

	TEE_Free(payload);
	return res;
}

// Called when the TA is created
TEE_Result TA_CreateEntryPoint(void) {
   return TEE_SUCCESS;
}

// Called when the TA is destroyed
void TA_DestroyEntryPoint(void) {
}

// open session
TEE_Result TA_OpenSessionEntryPoint(
	uint32_t __unused param_types,
	TEE_Param __unused params[4],
	void __unused **session
) {
	return TEE_SUCCESS;
}

// close session
void TA_CloseSessionEntryPoint(void __unused *session) {
}

// invoke command
TEE_Result TA_InvokeCommandEntryPoint(
	void __unused *session,
	uint32_t cmd,
	uint32_t param_types,
	TEE_Param params[4]
) {
	switch (cmd) {
		case Entry_SetKey:
			DMSG("Calling set_key");
			return set_key(param_types, params);
		case Entry_Attest:
			DMSG("Calling attest");
			return attest(param_types, params);
		case Entry_Disable:
			DMSG("Calling disable");
			return disable(param_types, params);
		case Entry_HandleInput:
			DMSG("Calling handle_input");
			return handle_input(param_types, params);
		case Entry_UserDefined:
			DMSG("Calling handle_entry");
			return handle_entry(param_types, params);
		default:
			EMSG("Command ID %d is not supported", cmd);
			return TEE_ERROR_NOT_SUPPORTED;
	}
}