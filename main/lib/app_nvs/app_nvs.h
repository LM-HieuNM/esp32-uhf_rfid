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

#ifdef __cplusplus
}
#endif

#endif /* MAIN_APP_NVS_H_ */
