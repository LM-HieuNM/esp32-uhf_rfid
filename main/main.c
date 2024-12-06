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
#define BUTTON_PIN (GPIO_NUM_9)

// static void send_hello(void *arg)
// {
//     static const char * data = "Hello client. Iam WSS";
//     ESP_LOGI(TAG, "Send Hello");
//     struct async_resp_arg *resp_arg = arg;
//     httpd_handle_t hd = resp_arg->hd;
//     int fd = resp_arg->fd;
//     httpd_ws_frame_t ws_pkt;
//     memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
//     ws_pkt.payload = (uint8_t*)data;
//     ws_pkt.len = strlen(data);
//     ws_pkt.type = HTTPD_WS_TYPE_TEXT;

//     httpd_ws_send_frame_async(hd, fd, &ws_pkt);
//     free(resp_arg);
// }



// Get all clients and send async message
// static void wss_server_send_messages(httpd_handle_t* server)
// {
//     bool send_messages = true;

//     // Send async message to all connected clients that use websocket protocol every 10 seconds
//     while (send_messages) {
//         ESP_LOGI(TAG, "Heap free: %ld", esp_get_free_heap_size());
//         vTaskDelay(10000 / portTICK_PERIOD_MS);

//         if (!*server) { // httpd might not have been created by now
//             continue;
//         }
//         size_t clients = max_clients;
//         int    client_fds[max_clients];
//         if (httpd_get_client_list(*server, &clients, client_fds) == ESP_OK) {
//             for (size_t i=0; i < clients; ++i) {
//                 int sock = client_fds[i];
//                 if (httpd_ws_get_fd_info(*server, sock) == HTTPD_WS_CLIENT_WEBSOCKET) {
//                     ESP_LOGI(TAG, "Active client (fd=%d) -> sending async message", sock);
//                     struct async_resp_arg *resp_arg = malloc(sizeof(struct async_resp_arg));
//                     assert(resp_arg != NULL);
//                     resp_arg->hd = *server;
//                     resp_arg->fd = sock;
//                     if (httpd_queue_work(resp_arg->hd, send_hello, resp_arg) != ESP_OK) {
//                         ESP_LOGE(TAG, "httpd_queue_work failed!");
//                         send_messages = false;
//                         break;
//                     }
//                 }
//             }
//         } else {
//             ESP_LOGE(TAG, "httpd_get_client_list failed!");
//             return;
//         }
//     }
// }

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
