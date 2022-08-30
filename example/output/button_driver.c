#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <authentic_execution.h>

#include <button_driver.h>

SM_OUTPUT_AUX(button_pressed, 16384);

SM_ENTRY(entry1, data, data_len) {

  DMSG("********Press the Button -- entry func -- button_driver SM*********\n");

  OUTPUT(button_pressed, data, data_len);
}