#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <authentic_execution.h>

#include <led_driver.h>

SM_INPUT(toggle_led, data, data_len) {

  printf("Button is Pressed, toggle LED\n");

}