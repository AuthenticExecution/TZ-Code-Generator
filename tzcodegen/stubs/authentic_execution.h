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

typedef struct {
  TEE_Param *params;
  uint32_t param_types;
} caller_t;

/* Definitions of fixed parameters */
#define ENTRY_START_INDEX 4
#define OUTPUT_DATA_MAX_SIZE 1024 * 1024 // total size (for all concurrent outputs) in bytes
#define MAX_CONCURRENT_OUTPUTS 32
#define MEASURE_TIME 1

/* Definition of Authentic Execution macros and parameters */
#define SM_OUTPUT_AUX(name, output_id)                                         \
  void name(unsigned char *data, uint32_t len) {                               \
    handle_output(output_id, data, len);                                       \
  }

#define SM_INPUT(name, data, len)                                              \
  void name(unsigned char *data, uint32_t len)

#define SM_ENTRY(name, data, len)                                              \
  void name(unsigned char *data, uint32_t len)

typedef void (*input_t)(unsigned char *, uint32_t);
typedef void (*entry_t)(unsigned char *, uint32_t);

/* Definition of Authentic Execution functions */
TEE_Result set_key(void);
TEE_Result disable(void);
TEE_Result attest(void);
void handle_output(uint16_t output_id, unsigned char *data_input, uint32_t data_len);
TEE_Result handle_input(void);
TEE_Result handle_entry(void);

#endif 
