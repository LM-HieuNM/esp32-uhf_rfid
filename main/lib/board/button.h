#ifndef _BUTTON_HPP
#define _BUTTON_HPP
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "iot_button.h"
#define BUTTON_1_TAP_BIT        (1 << 0)
#define BUTTON_2_TAP_BIT        (1 << 1)
#define BUTTON_5_TAP_BIT        (1 << 2)
extern EventGroupHandle_t button_event_group;
void board_init(void);

#endif