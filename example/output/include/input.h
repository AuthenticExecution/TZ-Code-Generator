#ifndef __TA_H__
#define __TA_H__

#include <tee_internal_api.h> 

// outputs
void button_pressed(TEE_Param params[4], unsigned char *data, uint32_t len);

// inputs

//entrypoint
void entry1(TEE_Param params[4], unsigned char *data, uint32_t len);


#endif