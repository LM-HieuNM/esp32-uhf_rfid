#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi_types.h"

#include "app_nvs.h"
#include "wifi_app.h"


// Tag for logging
static const char TAG[] = "app_nvs";

// NVS name space used for station mode credentials
const char app_nvs_sta_creds_namespace[] = "stacreds";
const char app_nvs_socket_creds_namespace[] = "socketcreds";
const char app_nvs_antenna_namespace[] = "antenna";
const char app_nvs_protocol_namespace[] = "protocol";

esp_err_t app_nvs_save_sta_creds(void)
{
	nvs_handle handle;
	esp_err_t esp_err;
	ESP_LOGI(TAG, "app_nvs_save_sta_creds: Saving station mode credentials to flash");

	wifi_config_t *wifi_sta_config = wifi_app_get_wifi_config();

	if (wifi_sta_config)
	{
		esp_err = nvs_open(app_nvs_sta_creds_namespace, NVS_READWRITE, &handle);
		if (esp_err != ESP_OK)
		{
			printf("app_nvs_save_sta_creds: Error (%s) opening NVS handle!\n", esp_err_to_name(esp_err));
			return esp_err;
		}

		// Set SSID
		esp_err = nvs_set_blob(handle, "ssid", wifi_sta_config->sta.ssid, MAX_SSID_LENGTH);
		if (esp_err != ESP_OK)
		{
			printf("app_nvs_save_sta_creds: Error (%s) setting SSID to NVS!\n", esp_err_to_name(esp_err));
			return esp_err;
		}

		// Set Password
		esp_err = nvs_set_blob(handle, "password", wifi_sta_config->sta.password, MAX_PASSWORD_LENGTH);
		if (esp_err != ESP_OK)
		{
			printf("app_nvs_save_sta_creds: Error (%s) setting Password to NVS!\n", esp_err_to_name(esp_err));
			return esp_err;
		}

		// Commit credentials to NVS
		esp_err = nvs_commit(handle);
		if (esp_err != ESP_OK)
		{
			printf("app_nvs_save_sta_creds: Error (%s) comitting credentials to NVS!\n", esp_err_to_name(esp_err));
			return esp_err;
		}
		nvs_close(handle);
		ESP_LOGI(TAG, "app_nvs_save_sta_creds: wrote wifi_sta_config: Station SSID: %s Password: %s", 
				wifi_sta_config->sta.ssid, wifi_sta_config->sta.password);
	}

	return ESP_OK;
}

bool app_nvs_load_sta_creds(void)
{
	nvs_handle handle;
	esp_err_t esp_err;

	ESP_LOGI(TAG, "app_nvs_load_sta_creds: Loading Wifi credentials from flash");

	if (nvs_open(app_nvs_sta_creds_namespace, NVS_READONLY, &handle) == ESP_OK)
	{
		wifi_config_t *wifi_sta_config = wifi_app_get_wifi_config();

		memset(wifi_sta_config, 0x00, sizeof(wifi_config_t));

		// Allocate buffer
		size_t wifi_config_size = sizeof(wifi_config_t);
		uint8_t *wifi_config_buff = (uint8_t*)malloc(sizeof(uint8_t) * wifi_config_size);
		memset(wifi_config_buff, 0x00, sizeof(wifi_config_size));

		// Load SSID
		wifi_config_size = sizeof(wifi_sta_config->sta.ssid);
		esp_err = nvs_get_blob(handle, "ssid", wifi_config_buff, &wifi_config_size);
		if (esp_err != ESP_OK)
		{
			free(wifi_config_buff);
			printf("app_nvs_load_sta_creds: (%s) no station SSID found in NVS\n", esp_err_to_name(esp_err));
			return false;
		}
		memcpy(wifi_sta_config->sta.ssid, wifi_config_buff, wifi_config_size);

		// Load Password
		wifi_config_size = sizeof(wifi_sta_config->sta.password);
		esp_err = nvs_get_blob(handle, "password", wifi_config_buff, &wifi_config_size);
		if (esp_err != ESP_OK)
		{
			free(wifi_config_buff);
			printf("app_nvs_load_sta_creds: (%s) retrieving password!\n", esp_err_to_name(esp_err));
			return false;
		}
		memcpy(wifi_sta_config->sta.password, wifi_config_buff, wifi_config_size);

		free(wifi_config_buff);
		nvs_close(handle);

		printf("app_nvs_load_sta_creds: SSID: %s Password: %s\n", wifi_sta_config->sta.ssid, wifi_sta_config->sta.password);
		return wifi_sta_config->sta.ssid[0] != '\0';
	}
	else
	{
		return false;
	}
}

esp_err_t app_nvs_clear_sta_creds(void)
{
	nvs_handle handle;
	esp_err_t esp_err;
	ESP_LOGI(TAG, "app_nvs_clear_sta_creds: Clearing Wifi station mode credentials from flash");

	esp_err = nvs_open(app_nvs_sta_creds_namespace, NVS_READWRITE, &handle);
	if (esp_err != ESP_OK)
	{
		printf("app_nvs_clear_sta_creds: Error (%s) opening NVS handle!\n", esp_err_to_name(esp_err));
		return esp_err;
	}

	// Erase credentials
	esp_err = nvs_erase_all(handle);
	if (esp_err != ESP_OK)
	{
		printf("app_nvs_clear_sta_creds: Error (%s) erasing station mode credentials!\n", esp_err_to_name(esp_err));
		return esp_err;
	}

	// Commit clearing credentials from NVS
	esp_err = nvs_commit(handle);
	if (esp_err != ESP_OK)
	{
		printf("app_nvs_clear_sta_creds: Error (%s) NVS commit!\n", esp_err_to_name(esp_err));
		return esp_err;
	}
	nvs_close(handle);

	printf("app_nvs_clear_sta_creds: returned ESP_OK\n");
	return ESP_OK;
}


// for socket

esp_err_t app_nvs_save_socket_creds(char* strAddr, char* strPort)
{
	nvs_handle handle;
	esp_err_t esp_err;
	ESP_LOGI(TAG, "app_nvs_save_socket_creds: Saving socket to flash");


	esp_err = nvs_open(app_nvs_socket_creds_namespace, NVS_READWRITE, &handle);
	if (esp_err != ESP_OK)
	{
		printf("app_nvs_save_socket_creds: Error (%s) opening NVS handle!\n", esp_err_to_name(esp_err));
		return esp_err;
	}

	// Set SSID
	esp_err = nvs_set_blob(handle, "address", strAddr, MAX_SSID_LENGTH);
	if (esp_err != ESP_OK)
	{
		printf("app_nvs_save_socket_creds: Error (%s) setting Address to NVS!\n", esp_err_to_name(esp_err));
		return esp_err;
	}

	// Set Port
	esp_err = nvs_set_blob(handle, "port", strPort, 4);
	if (esp_err != ESP_OK)
	{
		printf("app_nvs_save_socket_creds: Error (%s) setting Port to NVS!\n", esp_err_to_name(esp_err));
		return esp_err;
	}

	// Commit credentials to NVS
	esp_err = nvs_commit(handle);
	if (esp_err != ESP_OK)
	{
		printf("app_nvs_socket_creds_namespace: Error (%s) comitting credentials to NVS!\n", esp_err_to_name(esp_err));
		return esp_err;
	}
	nvs_close(handle);
	ESP_LOGI(TAG, "app_nvs_save_socket_creds: wrote socketAddr: Station Addr: %s Port: %s", strAddr, strPort);


	printf("app_nvs_save_socket_creds: returned ESP_OK\n");
	return ESP_OK;
}

bool app_nvs_load_socket_creds(void)
{
	nvs_handle handle;
	esp_err_t esp_err;

	ESP_LOGI(TAG, "app_nvs_load_socket_creds: Loading socket credentials from flash");

	if (nvs_open(app_nvs_sta_creds_namespace, NVS_READONLY, &handle) == ESP_OK)
	{

		// Allocate buffer
		size_t socket_size = 32;
		char*socketAddress = (char*)malloc(socket_size);
		memset(socketAddress, 0x00, sizeof(sizeof(uint8_t) * 32));

		// Load adrr
		esp_err = nvs_get_blob(handle, "address", socketAddress, &socket_size);
		if (esp_err != ESP_OK)
		{
			free(socketAddress);
			printf("app_nvs_load_socket_creds: (%s) no socket address found in NVS\n", esp_err_to_name(esp_err));
			return false;
		}

		// Load port
		socket_size = 4;
		char* socketPort = (char*)malloc(socket_size);

		esp_err = nvs_get_blob(handle, "port", socketPort, &socket_size);
		if (esp_err != ESP_OK)
		{
			free(socketPort);
			printf("app_nvs_load_sta_creds: (%s) retrieving port!\n", esp_err_to_name(esp_err));
			return false;
		}

		nvs_close(handle);

		printf("app_nvs_load_socket_creds: Address: %s Port: %s\n", socketAddress, socketPort);
		return true;
	}
	else
	{
		return false;
	}
}

esp_err_t app_nvs_save_antenna_config(antenna_config_t *config)
{
    nvs_handle handle;
    esp_err_t esp_err;
    ESP_LOGI(TAG, "app_nvs_save_antenna_config: Saving antenna config to flash");

    esp_err = nvs_open(app_nvs_antenna_namespace, NVS_READWRITE, &handle);
    if (esp_err != ESP_OK)
    {
        printf("app_nvs_save_antenna_config: Error (%s) opening NVS handle!\n", esp_err_to_name(esp_err));
        return esp_err;
    }

    // Lưu power
    esp_err = nvs_set_i32(handle, "power", config->power);
    if (esp_err != ESP_OK)
    {
        printf("app_nvs_save_antenna_config: Error (%s) saving power!\n", esp_err_to_name(esp_err));
        return esp_err;
    }

    // Lưu antenna array
    esp_err = nvs_set_blob(handle, "antennas", config->antennas, sizeof(config->antennas));
    if (esp_err != ESP_OK)
    {
        printf("app_nvs_save_antenna_config: Error (%s) saving antennas!\n", esp_err_to_name(esp_err));
        return esp_err;
    }

    // Commit
    esp_err = nvs_commit(handle);
    if (esp_err != ESP_OK)
    {
        printf("app_nvs_save_antenna_config: Error (%s) committing data to NVS!\n", esp_err_to_name(esp_err));
        return esp_err;
    }

    nvs_close(handle);
    ESP_LOGI(TAG, "app_nvs_save_antenna_config: Saved power: %d", config->power);
    return ESP_OK;
}

esp_err_t app_nvs_load_antenna_config(antenna_config_t *config)
{
    nvs_handle handle;
    esp_err_t esp_err;

    ESP_LOGI(TAG, "app_nvs_load_antenna_config: Loading antenna config from flash");

    if (nvs_open(app_nvs_antenna_namespace, NVS_READONLY, &handle) == ESP_OK)
    {
        // Load power
        int32_t power;
        esp_err = nvs_get_i32(handle, "power", &power);
        if (esp_err == ESP_OK)
        {
            config->power = power;
        }
        else if (esp_err == ESP_ERR_NVS_NOT_FOUND)
        {
            // Set default power
            config->power = 10;
            printf("app_nvs_load_antenna_config: No power value found, using default: %d\n", config->power);
        }
        else
        {
            printf("app_nvs_load_antenna_config: Error (%s) reading power!\n", esp_err_to_name(esp_err));
            nvs_close(handle);
            return esp_err;
        }

        // Load antennas
        size_t required_size = sizeof(config->antennas);
        esp_err = nvs_get_blob(handle, "antennas", config->antennas, &required_size);
        if (esp_err == ESP_ERR_NVS_NOT_FOUND)
        {
            // Set defaults: all off except antenna 1
            memset(config->antennas, false, sizeof(config->antennas));
            config->antennas[0] = true;
            printf("app_nvs_load_antenna_config: No antenna config found, using defaults\n");
        }
        else if (esp_err != ESP_OK)
        {
            printf("app_nvs_load_antenna_config: Error (%s) reading antennas!\n", esp_err_to_name(esp_err));
            nvs_close(handle);
            return esp_err;
        }

        nvs_close(handle);
        ESP_LOGI(TAG, "app_nvs_load_antenna_config: Loaded power: %d", config->power);
        return ESP_OK;
    }

    printf("app_nvs_load_antenna_config: Error opening NVS handle!\n");
    return ESP_FAIL;
}

esp_err_t app_nvs_save_protocol_config(protocol_config_t *config)
{
    // Validate input
    if (config == NULL) {
        ESP_LOGE(TAG, "app_nvs_save_protocol_config: NULL config pointer");
        return ESP_ERR_INVALID_ARG;
    }

    // Validate protocol type
    if (config->type != PROTOCOL_WEBSOCKET && config->type != PROTOCOL_BLE_HID) {
        ESP_LOGE(TAG, "app_nvs_save_protocol_config: Invalid protocol type: %d", config->type);
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle handle;
    esp_err_t esp_err;
    ESP_LOGI(TAG, "app_nvs_save_protocol_config: Saving protocol config to flash");

    esp_err = nvs_open(app_nvs_protocol_namespace, NVS_READWRITE, &handle);
    if (esp_err != ESP_OK)
    {
        ESP_LOGE(TAG, "app_nvs_save_protocol_config: Error (%s) opening NVS handle!", esp_err_to_name(esp_err));
        return esp_err;
    }

    // Save protocol type
    esp_err = nvs_set_i32(handle, "type", (int32_t)config->type);
    if (esp_err != ESP_OK)
    {
        ESP_LOGE(TAG, "app_nvs_save_protocol_config: Error (%s) saving protocol type!", esp_err_to_name(esp_err));
        nvs_close(handle);
        return esp_err;
    }

    // Save config based on protocol type
    if (config->type == PROTOCOL_WEBSOCKET)
    {
        // Validate websocket config
        if (strlen(config->websocket.url) == 0) {
            ESP_LOGE(TAG, "app_nvs_save_protocol_config: Empty websocket URL");
            nvs_close(handle);
            return ESP_ERR_INVALID_ARG;
        }
        if (config->websocket.port <= 0) {
            ESP_LOGE(TAG, "app_nvs_save_protocol_config: Invalid websocket port: %" PRId32, config->websocket.port);
            nvs_close(handle);
            return ESP_ERR_INVALID_ARG;
        }
        if (config->websocket.max_clients <= 0) {
            ESP_LOGE(TAG, "app_nvs_save_protocol_config: Invalid max clients: %" PRId32, config->websocket.max_clients);
            nvs_close(handle);
            return ESP_ERR_INVALID_ARG;
        }

        esp_err = nvs_set_str(handle, "ws_url", config->websocket.url);
        esp_err |= nvs_set_i32(handle, "ws_port", config->websocket.port);
        esp_err |= nvs_set_i32(handle, "ws_max_clients", config->websocket.max_clients);
    }
    else if (config->type == PROTOCOL_BLE_HID)
    {
        // Validate BLE config
        if (strlen(config->ble_hid.device_name) == 0) {
            ESP_LOGE(TAG, "app_nvs_save_protocol_config: Empty BLE device name");
            nvs_close(handle);
            return ESP_ERR_INVALID_ARG;
        }
        if (strlen(config->ble_hid.pin_code) == 0) {
            ESP_LOGE(TAG, "app_nvs_save_protocol_config: Empty BLE PIN");
            nvs_close(handle);
            return ESP_ERR_INVALID_ARG;
        }

        esp_err = nvs_set_str(handle, "ble_name", config->ble_hid.device_name);
        esp_err |= nvs_set_str(handle, "ble_pin", config->ble_hid.pin_code);
    }

    if (esp_err != ESP_OK)
    {
        ESP_LOGE(TAG, "app_nvs_save_protocol_config: Error saving protocol specific config!");
        nvs_close(handle);
        return esp_err;
    }

    // Commit
    esp_err = nvs_commit(handle);
    if (esp_err != ESP_OK)
    {
        ESP_LOGE(TAG, "app_nvs_save_protocol_config: Error (%s) committing data to NVS!", esp_err_to_name(esp_err));
        nvs_close(handle);
        return esp_err;
    }

    nvs_close(handle);
    ESP_LOGI(TAG, "app_nvs_save_protocol_config: Protocol config saved successfully");
    return ESP_OK;
}

esp_err_t app_nvs_load_protocol_config(protocol_config_t *config)
{
    nvs_handle handle;
    esp_err_t esp_err;
    int32_t protocol_type;

    ESP_LOGI(TAG, "app_nvs_load_protocol_config: Loading protocol config from flash");

    // Khởi tạo giá trị mặc định trước
    config->type = DEFAULT_PROTOCOL_TYPE;
    if (config->type == PROTOCOL_WEBSOCKET) {
        strcpy(config->websocket.url, DEFAULT_WS_URL);
        config->websocket.port = DEFAULT_WS_PORT;
        config->websocket.max_clients = DEFAULT_WS_MAX_CLIENTS;
    } else {
        strcpy(config->ble_hid.device_name, DEFAULT_BLE_DEVICE_NAME);
        strcpy(config->ble_hid.pin_code, DEFAULT_BLE_PIN);
    }

    // Nếu mở NVS thành công thì mới đọc và ghi đè lên giá trị mặc định
    if (nvs_open(app_nvs_protocol_namespace, NVS_READONLY, &handle) == ESP_OK)
    {
        // Load protocol type
        esp_err = nvs_get_i32(handle, "type", &protocol_type);
        if (esp_err == ESP_OK)
        {
            config->type = (protocol_type_t)protocol_type;
        }

        // Luôn load cả hai cấu hình, bất kể protocol type hiện tại
        // Load WebSocket config
        size_t required_size = sizeof(config->websocket.url);
        esp_err = nvs_get_str(handle, "ws_url", config->websocket.url, &required_size);
        if (esp_err != ESP_OK) {
            strcpy(config->websocket.url, DEFAULT_WS_URL);
        }
        
        esp_err = nvs_get_i32(handle, "ws_port", &config->websocket.port);
        if (esp_err != ESP_OK) {
            config->websocket.port = DEFAULT_WS_PORT;
        }
        
        esp_err = nvs_get_i32(handle, "ws_max_clients", &config->websocket.max_clients);
        if (esp_err != ESP_OK) {
            config->websocket.max_clients = DEFAULT_WS_MAX_CLIENTS;
        }
        
        // Load BLE HID config
        required_size = sizeof(config->ble_hid.device_name);
        esp_err = nvs_get_str(handle, "ble_name", config->ble_hid.device_name, &required_size);
        if (esp_err != ESP_OK) {
            strcpy(config->ble_hid.device_name, DEFAULT_BLE_DEVICE_NAME);
        }
        
        required_size = sizeof(config->ble_hid.pin_code);
        esp_err = nvs_get_str(handle, "ble_pin", config->ble_hid.pin_code, &required_size);
        if (esp_err != ESP_OK) {
            strcpy(config->ble_hid.pin_code, DEFAULT_BLE_PIN);
        }

        nvs_close(handle);
    } else {
        ESP_LOGW(TAG, "Error opening NVS handle, using default values");
    }

    return ESP_OK; // Luôn trả về OK vì đã có giá trị mặc định
}
