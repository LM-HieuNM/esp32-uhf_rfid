#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "iot_button.h"
#include "esp_log.h"
#include "app_nvs.h"
#include "button.h"


#define TAG "BUTTON"

#define BUTTON_IO_NUM           2
#define BUTTON_ACTIVE_LEVEL     0

EventGroupHandle_t button_event_group;


static void button_tap1_cb(void *arg, void *data)
{
    xEventGroupSetBits(button_event_group, BUTTON_1_TAP_BIT);
}

static void button_tap2_cb(void *arg, void *data)
{
    ESP_LOGI(TAG, "tap 2");
}

static void button_tap5_cb(void *arg, void *data)
{
    ESP_LOGI(TAG, "tap 5");
    app_nvs_set_temp_config(1);
    vTaskDelay(2000/portTICK_PERIOD_MS);
    esp_restart();
}

static void board_button_init(void)
{
    button_event_group = xEventGroupCreate();
    if (button_event_group == NULL) {
        ESP_LOGE(TAG, "Failed to create event group");
    }
    button_config_t config = {
        .type = BUTTON_TYPE_GPIO,
        .gpio_button_config = {
            .gpio_num = BUTTON_IO_NUM,
            .active_level = BUTTON_ACTIVE_LEVEL
        }
    };
    button_handle_t btn_handle = iot_button_create(&config);

    if (btn_handle) {
        button_event_config_t event_cfg_1tap = {
            .event = BUTTON_MULTIPLE_CLICK,
            .event_data = {
                .multiple_clicks = {
                    .clicks = 1
                }
            }
        };
        button_event_config_t event_cfg_2tap = {
            .event = BUTTON_MULTIPLE_CLICK,
            .event_data = {
                .multiple_clicks = {
                    .clicks = 2
                }
            }
        };
        button_event_config_t event_cfg_5tap = {
            .event = BUTTON_MULTIPLE_CLICK,
            .event_data = {
                .multiple_clicks = {
                    .clicks = 5
                }
            }
        };
        iot_button_register_event_cb(btn_handle, event_cfg_1tap, button_tap1_cb, NULL);
        iot_button_register_event_cb(btn_handle, event_cfg_2tap, button_tap2_cb, NULL);
        iot_button_register_event_cb(btn_handle, event_cfg_5tap, button_tap5_cb, NULL);
    }
}

void board_init(void)
{
    board_button_init();
}