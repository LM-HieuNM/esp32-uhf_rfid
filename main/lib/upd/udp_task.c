#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#define PORT 50000

static const char *TAG = "udp_task";

// Thêm struct để truyền thông số
typedef struct {
    char broadcast_ip[16];
    char local_ip[16];
    char mac_addr[18];
} udp_config_t;

static void udp_client_task(void *pvParameters)
{
    udp_config_t *config = (udp_config_t*)pvParameters;
    
    // Format payload với IP và MAC thực tế
    char payload[128];
    snprintf(payload, sizeof(payload), 
             "DISCOVERY:"     // Prefix
             "UHF-%s:"   // Device type & MAC
             "%s:"           // IP address
             "443:wss",      // Port & Protocol
             config->mac_addr,
             config->local_ip);

    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = inet_addr(config->broadcast_ip);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        free(config);
        vTaskDelete(NULL);
        return;
    }

    // Enable broadcast
    int broadcast = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
        ESP_LOGE(TAG, "Failed to set socket broadcast option: errno %d", errno);
        close(sock);
        free(config);
        vTaskDelete(NULL);
        return;
    }

    while (1) {
        int err = sendto(sock, payload, strlen(payload), 0, 
                        (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (err < 0) {
            ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
            break;
        }
        ESP_LOGI(TAG, "Discovery message sent to: %s", config->broadcast_ip);
        vTaskDelay(5000 / portTICK_PERIOD_MS);
    }

    free(config);
    vTaskDelete(NULL);
}

void udp_task_start(const char* broadcast_ip, const char* local_ip)
{
    udp_config_t *config = malloc(sizeof(udp_config_t));
    if (config == NULL) {
        ESP_LOGE(TAG, "Failed to allocate UDP config");
        return;
    }
    
    // Get MAC address
    uint8_t mac[6];
    esp_err_t err = esp_wifi_get_mac(WIFI_IF_STA, mac);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get MAC address: %d", err);
        free(config);
        return;
    }
    
    // Convert MAC to string (last 6 characters)
    snprintf(config->mac_addr, sizeof(config->mac_addr), 
             "%02X%02X%02X", 
             mac[3], mac[4], mac[5]);
    
    strncpy(config->broadcast_ip, broadcast_ip, sizeof(config->broadcast_ip));
    strncpy(config->local_ip, local_ip, sizeof(config->local_ip));
    
    ESP_LOGI(TAG, "Device MAC: %s", config->mac_addr);
    
    xTaskCreate(udp_client_task, "udp_client_task", 4096, config, 5, NULL);
}