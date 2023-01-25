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

key_t module_key = { {0}, TEE_HANDLE_NULL, TEE_HANDLE_NULL, TEE_HANDLE_NULL };
uint16_t current_nonce = 0;

caller_t caller = {NULL, 0};

static void measure_time(const char *msg, int index) {
#ifdef MEASURE_TIME
	TEE_Time t = {};
	TEE_GetREETime(&t);
	DMSG("tz_%s_%d: %u%06u us", msg, index, t.seconds, t.millis * 1000);
#endif
}

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
	pta_params[1].memref.buffer = module_key.key;
	pta_params[1].memref.size = SECURITY_BYTES;

	// open session to PTA
	TEE_UUID pta_uuid = ATTESTATION_UUID;
	TEE_Result res = TEE_OpenTASession(
		&pta_uuid,
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

	res = init_key(EncryptionType_Aes, &module_key);
	return res;
}

TEE_Result set_key(void) {
	const unsigned int ad_len = 7;
	const unsigned char *ad = caller.params[0].memref.buffer;
	const uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_NONE
	);
    Connection connection;

	// sanity checks
	if(
		caller.param_types != exp_param_types ||
		caller.params[0].memref.size != ad_len ||
		caller.params[1].memref.size != SECURITY_BYTES || 
		caller.params[2].memref.size != SECURITY_BYTES
	) {
		EMSG(
			"Bad inputs: %d/%d %d/%d %d/%d %d/%d",
			caller.param_types,
			exp_param_types,
			caller.params[0].memref.size,
			ad_len,
			caller.params[1].memref.size,
			SECURITY_BYTES,
			caller.params[2].memref.size,
			SECURITY_BYTES
		);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// check nonce: we only allow nonces >= current stored in memory
	uint16_t nonce_input = (ad[5] << 8) | ad[6];
	if(nonce_input < current_nonce) {
		EMSG("Invalid nonce");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// decrypt data
	TEE_Result res = decrypt_generic(
		EncryptionType_Aes,
		&module_key,
		caller.params[0].memref.buffer,
		caller.params[0].memref.size,
		caller.params[1].memref.buffer,
		caller.params[1].memref.size,
		connection.connection_key.key,
		caller.params[2].memref.buffer
	);

	if (res != TEE_SUCCESS) {
		EMSG("Failed to decrypt data: %x", res);
		return res;
	}

	current_nonce++;
	connection.encryption = ad[0];
	connection.conn_id = (ad[1] << 8) | ad[2];
	connection.io_id = (ad[3] << 8) | ad[4];
	connection.nonce = 0;

	res = init_key(connection.encryption, &connection.connection_key);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to initialize key: %x", res);
		return res;
	}

	DMSG("Adding connection");

	// replace if existing
	if(!connections_replace(&connection)) {
		connections_add(&connection);
	}

	return TEE_SUCCESS;
}

TEE_Result disable(void) {
	const unsigned int ad_len = 2, cipher_len = 2;
	const unsigned char *ad = caller.params[0].memref.buffer;
	const uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_NONE
	);

	// sanity checks
	if(
		caller.param_types != exp_param_types ||
		caller.params[0].memref.size != ad_len ||
		caller.params[1].memref.size != cipher_len || 
		caller.params[2].memref.size != SECURITY_BYTES
	) {
		EMSG(
			"Bad inputs: %d/%d %d/%d %d/%d %d/%d",
			caller.param_types,
			exp_param_types,
			caller.params[0].memref.size,
			ad_len,
			caller.params[1].memref.size,
			cipher_len,
			caller.params[2].memref.size,
			SECURITY_BYTES
		);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// check nonce: we only allow nonces >= current stored in memory
	uint16_t nonce_input = (ad[0] << 8) | ad[1];
	if(nonce_input < current_nonce) {
		EMSG("Invalid nonce");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	unsigned char decrypted_nonce[cipher_len];

	// decrypt data
	TEE_Result res = decrypt_generic(
		EncryptionType_Aes,
		&module_key,
		caller.params[0].memref.buffer,
		caller.params[0].memref.size,
		caller.params[1].memref.buffer,
		caller.params[1].memref.size,
		decrypted_nonce,
		caller.params[2].memref.buffer
	);

	if (res != TEE_SUCCESS) {
		EMSG("Failed to decrypt data: %x", res);
		return res;
	}

	current_nonce++;

	// all done: deleting all connections
	DMSG("Deleting all connections");
	delete_all_connections();
	return TEE_SUCCESS;
}

TEE_Result attest(void) {
	const uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	// sanity checks
	if(
		caller.param_types != exp_param_types ||
		caller.params[0].memref.size <= 0 ||
		caller.params[1].memref.size != SECURITY_BYTES
	) {
		EMSG(
			"Bad inputs: %d/%d %d %d/%d",
			caller.param_types,
			exp_param_types,
			caller.params[0].memref.size,
			caller.params[1].memref.size,
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
		&module_key,
		caller.params[0].memref.buffer,
		caller.params[0].memref.size,
		NULL,
		0,
		NULL,
		tag
	);

	if(res == TEE_SUCCESS) {
		caller.params[1].memref.size = SECURITY_BYTES;
		TEE_MemMove(caller.params[1].memref.buffer, tag, caller.params[1].memref.size);
    }
    else {
    	EMSG("MAC generation failed: %x", res);
    }

	return res;
}

void handle_output(
	uint16_t output_id,
	unsigned char *data_input,
	uint32_t data_len
) {
	DMSG("Handling output ID %d. Data size: %d", output_id, data_len);

	uint32_t total_data_size = caller.params[0].value.a; // data size so far
	uint32_t total_outputs = caller.params[0].value.b; // outputs already called so far

	// find offsets in output buffers
	unsigned char *conn_id_offset = (unsigned char *) caller.params[1].memref.buffer + 2 * total_outputs;
	unsigned char *payload_offset = (unsigned char *) caller.params[2].memref.buffer + total_data_size;

	// iterate over all connections for this output and compute payload+MAC
	for(
		Node *node = connections_get_head();
		node != NULL; 
		node = node->next
	) {
		Connection* conn = &node->connection;
		if(conn->io_id != output_id) continue;

		// check if we still have some space left in the buffers
		if(
			total_data_size + 4 + data_len + SECURITY_BYTES > OUTPUT_DATA_MAX_SIZE ||
			total_outputs >= MAX_CONCURRENT_OUTPUTS
		) {
			EMSG("WARNING: buffers are full, cannot accept new outputs");
			break;	
		}

		DMSG("Computing payload for connection %d", conn->conn_id);

		measure_time("handle_output_before_encryption", conn->encryption);

		// reverse nonce and conn_id (i.e., convert from little to big endian)
		uint16_t nonce_rev = conn->nonce << 8 | conn->nonce >> 8;

		// set conn_id and data length
		TEE_MemMove(conn_id_offset, (void *) &conn->conn_id, 2);
		TEE_MemMove(payload_offset, (void *) &data_len, 4);

		// encrypt payload
		TEE_Result res = encrypt_generic(
			conn->encryption,
			&conn->connection_key,
			(void *) &nonce_rev, // nonce is the associated data
			2,
			data_input,
			data_len,
			payload_offset + 4,
			payload_offset + 4 + data_len
		);

		if(res != TEE_SUCCESS) {
			EMSG(
				"Failed to encrypt payload for connection %d of output %d: %x",
				conn->conn_id,
				output_id,
				res
			);
			continue;
		}

		measure_time("handle_output_after_encryption", conn->encryption);

		conn->nonce = conn->nonce + 1;

		// update variables
		total_data_size += 4 + data_len + SECURITY_BYTES;
		total_outputs++;

		// update offsets
		conn_id_offset += 2;
		payload_offset += 4 + data_len + SECURITY_BYTES;
	}

	//update total number of connections and offset
	caller.params[0].value.a = total_data_size;
	caller.params[0].value.b = total_outputs;
	DMSG("handle_output completed");
}

TEE_Result handle_input(void) {
	const uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_MEMREF_INPUT
	);

	// sanity checks
	if(
		caller.param_types != exp_param_types ||
		caller.params[1].memref.size < 2 * MAX_CONCURRENT_OUTPUTS || // connection IDs
		caller.params[2].memref.size < OUTPUT_DATA_MAX_SIZE + SECURITY_BYTES * MAX_CONCURRENT_OUTPUTS || // payloads
		caller.params[3].memref.size < SECURITY_BYTES // tag
	) {
		EMSG(
			"Bad inputs: %d/%d %d/%d %d/%d %d/%d",
			caller.param_types,
			exp_param_types,
			caller.params[1].memref.size,
			2 * MAX_CONCURRENT_OUTPUTS,
			caller.params[2].memref.size,
			OUTPUT_DATA_MAX_SIZE + SECURITY_BYTES * MAX_CONCURRENT_OUTPUTS,
			caller.params[3].memref.size,
			SECURITY_BYTES
		);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	unsigned int payload_size = caller.params[0].value.a;
	uint16_t conn_id = caller.params[0].value.b;

	DMSG("Handling input of connection ID: %d", conn_id);

	Connection* conn = connections_get(conn_id);
	if(conn == NULL) {
		EMSG("No connection found with ID %d", conn_id);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	measure_time("handle_input_before_decryption", conn->encryption);

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
		&conn->connection_key,
		(void *) &nonce_rev,
		2,
		caller.params[2].memref.buffer,
		payload_size,
		payload,
		caller.params[3].memref.buffer
	);

	if (res != TEE_SUCCESS) {
		EMSG("Failed to decrypt data: %x", res);
		TEE_Free(payload);
		return res;
	}

	measure_time("handle_input_after_decryption", conn->encryption);

	conn->nonce = conn->nonce + 1;
	// params[0] is used to store data for possible outputs
	caller.params[0].value.a = 0;
	caller.params[0].value.b = 0;
	
	// call input function
	if(conn->io_id < NUM_INPUTS) {
		input_funcs[conn->io_id](
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

	measure_time("handle_input_after_handler", 0);
	return res;
}

TEE_Result handle_entry(void) {
	const uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_MEMREF_INOUT,
		TEE_PARAM_TYPE_NONE
	);

	// sanity checks
	if(
		caller.param_types != exp_param_types ||
		caller.params[1].memref.size < 2 * MAX_CONCURRENT_OUTPUTS || // connection IDs
		caller.params[2].memref.size < OUTPUT_DATA_MAX_SIZE + SECURITY_BYTES * MAX_CONCURRENT_OUTPUTS // payloads
	) {
		EMSG(
			"Bad inputs: %d/%d %d/%d %d/%d",
			caller.param_types,
			exp_param_types,
			caller.params[1].memref.size,
			2 * MAX_CONCURRENT_OUTPUTS,
			caller.params[2].memref.size,
			OUTPUT_DATA_MAX_SIZE + SECURITY_BYTES * MAX_CONCURRENT_OUTPUTS
		);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	unsigned int payload_size = caller.params[0].value.a;
	uint16_t entry_id = caller.params[0].value.b;

	DMSG("Handling custom entry point with ID: %d", entry_id);

	// copy input payload into a buffer (params[2] will be used for outputs)
	unsigned char *payload = TEE_Malloc(payload_size, 0);
	if(payload == NULL) {
		EMSG("Failed to allocate payload for entry point");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TEE_MemMove(payload, caller.params[2].memref.buffer, payload_size);

	// params[0] is used to store data for possible outputs
	caller.params[0].value.a = 0;
	caller.params[0].value.b = 0;

	// call entry point
	TEE_Result res = TEE_SUCCESS;
	if(
		entry_id - ENTRY_START_INDEX >= 0 &&
		entry_id - ENTRY_START_INDEX < NUM_ENTRIES
	) {
		entry_funcs[entry_id - ENTRY_START_INDEX](
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
	// copy params pointer to global variable
	// so it would not be necessary to propagate it everywhere
	caller.params = params;
	caller.param_types = param_types;

	switch (cmd) {
		case Entry_SetKey:
			DMSG("Calling set_key");
			return set_key();
		case Entry_Attest:
			DMSG("Calling attest");
			return attest();
		case Entry_Disable:
			DMSG("Calling disable");
			return disable();
		case Entry_HandleInput:
			DMSG("Calling handle_input");
			return handle_input();
		case Entry_UserDefined:
			DMSG("Calling handle_entry");
			return handle_entry();
		default:
			EMSG("Command ID %d is not supported", cmd);
			return TEE_ERROR_NOT_SUPPORTED;
	}
}