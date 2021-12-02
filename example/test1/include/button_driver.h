
#include <tee_internal_api.h> 


// outputs
void button_pressed(void *session, uint32_t param_types, TEE_Param params[4],unsigned char *data, uint32_t len);

// inputs

//entrypoint
void entry1(void *session, uint32_t param_types, TEE_Param params[4],unsigned char *data, uint32_t len);

