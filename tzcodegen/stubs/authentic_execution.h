#ifndef TA_H
#define TA_H

#include <tee_internal_api.h>
	
#define TA_AES_ALGO_ECB			0
#define TA_AES_ALGO_CBC			1
#define TA_AES_ALGO_GCM			2

#define TA_AES_SIZE_128BIT		(128 / 8)
#define TA_AES_SIZE_256BIT		(256 / 8)

#define TA_AES_MODE_ENCODE		        1
#define TA_AES_MODE_DECODE		        0

#define AES                     0 // aes-gcm-128
#define SPONGENT                1 // spongent-128


/* The function IDs implemented in this TA */
#define SET_KEY                               0
#define ATTEST                                1
#define HANDLE_INPUT                          2
#define ENTRY                                 3


TEE_Result handle_input(void *session, uint32_t param_types, TEE_Param params[4]);

void handle_output(void *session, uint32_t output_id, uint32_t param_types,
                   TEE_Param params[4], unsigned char *data_input, uint32_t data_len);

//------------------------------------------------------------------------------

#define SM_OUTPUT_AUX(name, output_id)                                         \
  void name(void *session, uint32_t param_types, TEE_Param params[4],          \
            unsigned char *data, uint32_t len) {                               \
    handle_output(session, output_id, param_types, params, data, len);         \
  }

#define SM_INPUT(name, data, len)                                              \
  void name(void *session, uint32_t param_types, TEE_Param params[4],          \
            unsigned char *data, uint32_t len)

#define SM_ENTRY(name, data, len)                                              \
  void name(void *session, uint32_t param_types, TEE_Param params[4],          \
            unsigned char *data, uint32_t len)

#define OUTPUT(name, data, len) name(session, param_types, params, data, len)

#endif 
