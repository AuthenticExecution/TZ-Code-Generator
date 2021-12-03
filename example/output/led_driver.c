#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <authentic_execution.h>

#include <led_driver.h>

SM_INPUT(toggle_led, data, data_len) {

  DMSG("Button is Pressed, toggle LED\n");

  for(int i = 0; i < data_len; i++){
		  		DMSG("%2X", data[i]);
	}

}