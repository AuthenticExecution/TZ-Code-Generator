
SM_INPUT(toggle_led, data, data_len) {

  DMSG("Button is Pressed, toggle LED\n");

  for(int i = 0; i < data_len; i++){
		  		DMSG("%2X", data[i]);
	}

}