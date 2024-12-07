#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_wifi.h"
#include "protocol_examples_common.h"
#include "lwip/sockets.h"
#include <esp_https_server.h>
#include "keep_alive.h"
#include "sdkconfig.h"
#include "driver/gpio.h"
#include "button.h"
#include "TagManage.hpp"
#include "esp_hid_device_main.h"
#include "wifi_app.h"
#include "app_nvs.h"
#include <inttypes.h>

static const char *TAG = "wss_main";

void app_main(void)
{
    
    esp_err_t ret = nvs_flash_init();
	if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
	{
		ESP_ERROR_CHECK(nvs_flash_erase());
		ret = nvs_flash_init();
	}
    ESP_ERROR_CHECK(ret);
    board_init();

    protocol_config_t protocol_config;
    app_nvs_load_protocol_config(&protocol_config);

    if(protocol_config.type == PROTOCOL_WEBSOCKET){
        wifi_app_start();
    }else if(protocol_config.type == PROTOCOL_BLE_HID){
        ESP_LOGI(TAG, "BLE HID");
        ESP_LOGI(TAG, "Device name: %s", protocol_config.ble_hid.device_name);
        uint32_t pin_code = strtoul(protocol_config.ble_hid.pin_code, NULL, 10);
        ESP_LOGI(TAG, "Pin code: %" PRIu32, pin_code);
        ble_hid_init(protocol_config.ble_hid.device_name, pin_code);
    }

    tag_manager_init(protocol_config.type);
}
