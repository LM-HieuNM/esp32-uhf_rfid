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
#include "wifi_app.h"

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
    wifi_app_start();
    tag_manager_init();
    // wss_server_send_messages(&server);
}
