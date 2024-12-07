/*
 * app_nvs.h
 *
 *  Created on: Oct 28, 2021
 *      Author: kjagu
 */

#ifndef MAIN_APP_NVS_H_
#define MAIN_APP_NVS_H_

#include "TagManage.hpp"

#ifdef __cplusplus
extern "C" {
#endif


// Default values for protocol config
#define DEFAULT_WS_URL              "wss://localhost"
#define DEFAULT_WS_PORT             443
#define DEFAULT_WS_MAX_CLIENTS      1
#define DEFAULT_BLE_DEVICE_NAME     "UHF_HID"
#define DEFAULT_BLE_PIN             "123456"
#define DEFAULT_PROTOCOL_TYPE        PROTOCOL_WEBSOCKET

// Định nghĩa các protocol type
typedef enum {
    PROTOCOL_WEBSOCKET = 0,
    PROTOCOL_BLE_HID = 1
} protocol_type_t;

typedef struct {
    protocol_type_t type;
    struct {
        char url[128];
        int32_t port;
        int32_t max_clients;
    } websocket;
    struct {
        char device_name[64];
        char pin_code[7];
    } ble_hid;
} protocol_config_t;

typedef struct {
    int power;
    bool antennas[16];
} antenna_config_t;
extern antenna_config_t current_antenna_config;

/**
 * Saves station mode Wifi credentials to NVS
 * @return ESP_OK if successful.
 */
esp_err_t app_nvs_save_sta_creds(void);

/**
 * Loads the previously saved credentials from NVS.
 * @return true if previously saved credentials were found.
 */
bool app_nvs_load_sta_creds(void);

/**
 * Clears station mode credentials from NVS
 * @return ESP_OK if successful.
 */
esp_err_t app_nvs_clear_sta_creds(void);

esp_err_t app_nvs_save_socket_creds(char* strAddr, char* strPort);

bool app_nvs_load_socket_creds(void);

esp_err_t app_nvs_save_antenna_config(antenna_config_t *config);
esp_err_t app_nvs_load_antenna_config(antenna_config_t *config);

esp_err_t app_nvs_save_protocol_config(protocol_config_t *config);
esp_err_t app_nvs_load_protocol_config(protocol_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* MAIN_APP_NVS_H_ */
