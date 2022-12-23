
SM_OUTPUT(button_pressed);

SM_ENTRY(entry1, data, data_len) {

  DMSG("********Press the Button -- entry func -- button_driver SM*********");

  OUTPUT(button_pressed, data, data_len);
}