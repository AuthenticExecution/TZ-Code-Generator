
SM_OUTPUT(button_pressed);

SM_ENTRY(entry1, data, data_len) {

  printf("********Press the Button -- entry func -- button_driver SM*********\n");

  OUTPUT(button_pressed, data, data_len);
}