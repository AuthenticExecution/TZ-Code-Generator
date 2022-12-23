#ifndef __AUTHENTIC_EXECUTION_H__
#define __AUTHENTIC_EXECUTION_H__

#include <tee_internal_api.h>

typedef enum {
    Entry_SetKey,
    Entry_Attest,
    Entry_Disable,
    Entry_HandleInput,
    Entry_UserDefined
} EntrypointID;

#define ENTRY_START_INDEX 4

/* Definition of Authentic Execution macros and parameters */
#define SM_OUTPUT_AUX(name, output_id)                                         \
  void name(void *session, TEE_Param params[4],                                \
            unsigned char *data, uint32_t len) {                               \
    handle_output(session, output_id, params, data, len);                      \
  }

#define SM_INPUT(name, data, len)                                              \
  void name(void *session, TEE_Param params[4],                                \
            unsigned char *data, uint32_t len)

#define SM_ENTRY(name, data, len)                                              \
  void name(void *session, TEE_Param params[4],                                \
            unsigned char *data, uint32_t len)

#define OUTPUT(name, data, len) name(session, params, data, len)

typedef void (*input_t)(void *, TEE_Param *, unsigned char *, uint32_t);
typedef void (*entry_t)(void *, TEE_Param *, unsigned char *, uint32_t);

/* Definition of Authentic Execution functions */
TEE_Result set_key(
	void *session,
	uint32_t param_types,
	TEE_Param params[4]
);

TEE_Result disable(
	void *session,
	uint32_t param_types,
	TEE_Param params[4]
);

TEE_Result attest(
	void *session,
	uint32_t param_types,
	TEE_Param params[4]
);

void handle_output(
  void *session,
  uint32_t output_id,
  TEE_Param params[4],
  unsigned char *data_input,
  uint32_t data_len
);

TEE_Result handle_input(
  void *session,
  uint32_t param_types,
  TEE_Param params[4]
);

TEE_Result handle_entry(
	void *session,
	uint32_t param_types,
	TEE_Param params[4]
);

#endif 
