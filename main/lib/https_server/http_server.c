#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_wifi.h"
#include "lwip/ip4_addr.h"
#include "sys/param.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "keep_alive.h"
#include "TagManage.hpp"
#include "cJSON.h"
#include "app_nvs.h"
#include "wifi_app.h"
#include "tasks_common.h"
#include "http_server.h"
#include <inttypes.h>
#define MAX_ANTENNA_COUNT 16
static const char TAG[] = "https_server";
static const size_t max_clients = 4;
static const int KEEPALIVE_TIMEOUT = 30;    // 30 giây
static const int KEEPALIVE_INTERVAL = 15;   // 15 giây
static const int MAX_RETRY = 3;         

static int g_wifi_connect_status = NONE;
static int g_fw_update_status = OTA_UPDATE_PENDING;

static httpd_handle_t http_server_handle = NULL;
static TaskHandle_t task_http_server_monitor = NULL;
static QueueHandle_t http_server_monitor_queue_handle;

static protocol_config_t g_protocol_config;

struct async_resp_arg {
    httpd_handle_t hd;
    int fd;
    void* data;
};

const esp_timer_create_args_t fw_update_reset_args = {
		.callback = &http_server_fw_update_reset_callback,
		.arg = NULL,
		.dispatch_method = ESP_TIMER_TASK,
		.name = "fw_update_reset"
};
esp_timer_handle_t fw_update_reset;

extern const uint8_t jquery_3_3_1_min_js_start[]	asm("_binary_jquery_3_3_1_min_js_start");
extern const uint8_t jquery_3_3_1_min_js_end[]		asm("_binary_jquery_3_3_1_min_js_end");
extern const uint8_t index_html_start[]				asm("_binary_index_html_start");
extern const uint8_t index_html_end[]				asm("_binary_index_html_end");
extern const uint8_t app_css_start[]				asm("_binary_app_css_start");
extern const uint8_t app_css_end[]					asm("_binary_app_css_end");
extern const uint8_t app_js_start[]					asm("_binary_app_js_start");
extern const uint8_t app_js_end[]					asm("_binary_app_js_end");
extern const uint8_t favicon_ico_start[]			asm("_binary_favicon_ico_start");
extern const uint8_t favicon_ico_end[]				asm("_binary_favicon_ico_end");

static esp_err_t ws_handler(httpd_req_t *req);
static esp_err_t http_server_jquery_handler(httpd_req_t *req);
static esp_err_t http_server_index_html_handler(httpd_req_t *req);
static esp_err_t http_server_app_css_handler(httpd_req_t *req);
static esp_err_t http_server_app_js_handler(httpd_req_t *req);
static esp_err_t http_server_favicon_ico_handler(httpd_req_t *req);
static esp_err_t http_server_wifi_connect_json_handler(httpd_req_t *req);
static esp_err_t http_server_get_wifi_connect_info_json_handler(httpd_req_t *req);
static esp_err_t http_server_wifi_disconnect_json_handler(httpd_req_t *req);
static esp_err_t http_server_reboot_handler(httpd_req_t *req);

/*****************************************************************/
/*********************HTTPS SERVER HANDLER************************/
/*****************************************************************/
static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        ESP_LOGI(TAG, "WebSocket handshake for fd %d", httpd_req_to_sockfd(req));
        return ESP_OK;
    }

    httpd_ws_frame_t ws_pkt;
    uint8_t *buf = NULL;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));

    // Set max_len = 0 to get the frame len
    esp_err_t ret = httpd_ws_recv_frame(req, &ws_pkt, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ws_recv_frame failed with %d", ret);
        return ret;
    }

    if (ws_pkt.len) {
        buf = calloc(1, ws_pkt.len + 1);
        if (buf == NULL) {
            ESP_LOGE(TAG, "Failed to allocate memory");
            return ESP_ERR_NO_MEM;
        }
        ws_pkt.payload = buf;
        ret = httpd_ws_recv_frame(req, &ws_pkt, ws_pkt.len);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "httpd_ws_recv_frame failed with %d", ret);
            free(buf);
            return ret;
        }
    }

    switch (ws_pkt.type) {
        case HTTPD_WS_TYPE_TEXT:
        {
            ESP_LOGI(TAG, "Received text message: %s", (char*)ws_pkt.payload);
            
            // Parse JSON
            cJSON *root = cJSON_Parse((char*)ws_pkt.payload);
            if (root != NULL) {
                // Lấy command và command_id
                cJSON *command = cJSON_GetObjectItem(root, "command");
                cJSON *command_id = cJSON_GetObjectItem(root, "command_id");
                
                if (command != NULL && cJSON_IsString(command)) {
                    bool success = false;
                    
                    if (strcmp(command->valuestring, "start") == 0) {
                        // Xử lý lệnh start
                        cJSON *payload = cJSON_GetObjectItem(root, "payload");
                        bool doNotPersistState = false;
                        
                        if (payload != NULL && cJSON_IsObject(payload)) {
                            cJSON *persistState = cJSON_GetObjectItem(payload, "doNotPersistState");
                            if (persistState != NULL && cJSON_IsBool(persistState)) {
                                doNotPersistState = cJSON_IsTrue(persistState);
                            }
                        }
                        
                        startInventory();
                        success = true;
                    }
                    else if (strcmp(command->valuestring, "stop") == 0) {
                        // Xử lý lệnh stop
                        stopInventory();
                        success = true;
                    }
                    
                    if (success) {
                        // Tạo response JSON
                        cJSON *response = cJSON_CreateObject();
                        cJSON_AddStringToObject(response, "command", command->valuestring);
                        if (command_id != NULL && cJSON_IsString(command_id)) {
                            cJSON_AddStringToObject(response, "command_id", command_id->valuestring);
                        }
                        cJSON_AddStringToObject(response, "response", "success");
                        cJSON_AddObjectToObject(response, "payload");  // Empty payload object
                        
                        char *response_str = cJSON_Print(response);
                        
                        // Gửi response
                        httpd_ws_frame_t ws_response = {
                            .final = true,
                            .fragmented = false,
                            .type = HTTPD_WS_TYPE_TEXT,
                            .payload = (uint8_t*)response_str,
                            .len = strlen(response_str)
                        };
                        ret = httpd_ws_send_frame(req, &ws_response);
                        
                        // Giải phóng bộ nhớ
                        free(response_str);
                        cJSON_Delete(response);
                    }
                }
            }
            cJSON_Delete(root);
            
            if (ret != ESP_OK) {
                ESP_LOGE(TAG, "httpd_ws_send_frame failed with %d", ret);
            }
            break;
        }
            
        case HTTPD_WS_TYPE_BINARY:
            // Xử lý binary message
            ESP_LOGI(TAG, "Received binary message, len=%d", ws_pkt.len);
            break;
            
        case HTTPD_WS_TYPE_PONG:
            ESP_LOGD(TAG, "Received PONG from client fd %d", httpd_req_to_sockfd(req));
            wss_keep_alive_t h = httpd_get_global_user_ctx(req->handle);
            if (h) {
                wss_keep_alive_client_is_active(h, httpd_req_to_sockfd(req));
            }
            break;
            
        case HTTPD_WS_TYPE_PING:
            // Tự động trả lời PING bằng PONG
            ws_pkt.type = HTTPD_WS_TYPE_PONG;
            ret = httpd_ws_send_frame(req, &ws_pkt);
            if (ret != ESP_OK) {
                ESP_LOGE(TAG, "httpd_ws_send_frame failed with %d", ret);
            }
            break;
            
        default:
            ESP_LOGI(TAG, "Received unknown message type: %d", ws_pkt.type);
            break;
    }
    
    free(buf);
    return ESP_OK;
}

static esp_err_t http_server_jquery_handler(httpd_req_t *req)
{
	ESP_LOGI(TAG, "Jquery requested from fd %d", httpd_req_to_sockfd(req));

	httpd_resp_set_type(req, "application/javascript");
	httpd_resp_send(req, (const char *)jquery_3_3_1_min_js_start, jquery_3_3_1_min_js_end - jquery_3_3_1_min_js_start);

	return ESP_OK;
}


static esp_err_t http_server_index_html_handler(httpd_req_t *req)
{
	ESP_LOGI(TAG, "index.html requested from fd %d", httpd_req_to_sockfd(req));

	httpd_resp_set_type(req, "text/html");
	httpd_resp_send(req, (const char *)index_html_start, index_html_end - index_html_start);

	return ESP_OK;
}

static esp_err_t http_server_app_css_handler(httpd_req_t *req)
{
	ESP_LOGI(TAG, "app.css requested");

	httpd_resp_set_type(req, "text/css");
	httpd_resp_send(req, (const char *)app_css_start, app_css_end - app_css_start);

	return ESP_OK;
}

static esp_err_t http_server_app_js_handler(httpd_req_t *req)
{
	ESP_LOGI(TAG, "app.js requested from fd %d", httpd_req_to_sockfd(req));

	httpd_resp_set_type(req, "application/javascript");
	httpd_resp_send(req, (const char *)app_js_start, app_js_end - app_js_start);

	return ESP_OK;
}

static esp_err_t http_server_favicon_ico_handler(httpd_req_t *req)
{
	ESP_LOGI(TAG, "favicon.ico requested");

	httpd_resp_set_type(req, "image/x-icon");
	httpd_resp_send(req, (const char *)favicon_ico_start, favicon_ico_end - favicon_ico_start);

	return ESP_OK;
}

esp_err_t http_server_OTA_update_handler(httpd_req_t *req)
{
    esp_ota_handle_t ota_handle;
    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    
    // Kiểm tra partition
    if (update_partition == NULL) {
        ESP_LOGE(TAG, "OTA update partition not found!");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA partition error");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Writing to partition subtype %u at offset 0x%" PRIx32,
             update_partition->subtype, update_partition->address);

    // Khởi tạo OTA
    esp_err_t err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA begin failed");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "esp_ota_begin succeeded");

    char buf[1024];
    int received;
    bool is_first_block = true;
    uint32_t binary_file_length = 0;
    uint32_t content_length = req->content_len;
    int retry_count = 0;
    const int MAX_RETRIES = 5;
    
    ESP_LOGI(TAG, "Starting OTA update, content length: %" PRIu32, content_length);
    
    while (binary_file_length < content_length) {
        received = httpd_req_recv(req, buf, MIN(content_length - binary_file_length, sizeof(buf)));
        
        if (received < 0) {
            if (received == HTTPD_SOCK_ERR_TIMEOUT) {
                ESP_LOGW(TAG, "Timeout waiting for data, retrying... (%d/%d)", 
                        retry_count + 1, MAX_RETRIES);
                if (++retry_count >= MAX_RETRIES) {
                    ESP_LOGE(TAG, "Max retries reached, aborting OTA");
                    esp_ota_abort(ota_handle);
                    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, 
                                      "Too many timeouts during OTA");
                    return ESP_FAIL;
                }
                continue;
            }
            ESP_LOGE(TAG, "Error during OTA receive: %d", received);
            esp_ota_abort(ota_handle);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA receive failed");
            return ESP_FAIL;
        } else if (received == 0) {
            if (binary_file_length >= content_length - 200) {
                ESP_LOGI(TAG, "OTA receive nearly complete (actual: %" PRIu32 ", expected: %" PRIu32 ")", 
                         binary_file_length, content_length);
                break;
            }
            
            ESP_LOGW(TAG, "Connection closed at %" PRIu32 "/%" PRIu32 " bytes, retrying... (%d/%d)", 
                    binary_file_length, content_length, retry_count + 1, MAX_RETRIES);
            
            if (++retry_count >= MAX_RETRIES) {
                ESP_LOGE(TAG, "Max retries reached, aborting OTA");
                esp_ota_abort(ota_handle);
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, 
                                  "Connection closed too many times");
                return ESP_FAIL;
            }
            
            static uint32_t last_progress = 0;
            if (binary_file_length == last_progress && 
                binary_file_length < content_length - 1024) {
                ESP_LOGE(TAG, "No progress after retry, aborting OTA");
                esp_ota_abort(ota_handle);
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, 
                                  "Upload stalled");
                return ESP_FAIL;
            }
            last_progress = binary_file_length;
            
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        
        retry_count = 0; // Reset retry counter on successful receive

        if (is_first_block) {
            char *body_start = strstr(buf, "\r\n\r\n");
            if (body_start) {
                body_start += 4;
                int body_length = received - (body_start - buf);
                if (body_length > 0) {
                    esp_err_t err = esp_ota_write(ota_handle, body_start, body_length);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "esp_ota_write failed (%s)", esp_err_to_name(err));
                        esp_ota_abort(ota_handle);
                        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA write failed");
                        return ESP_FAIL;
                    }
                    binary_file_length += body_length;
                }
            }
            is_first_block = false;
        } else {
            esp_err_t err = esp_ota_write(ota_handle, buf, received);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "esp_ota_write failed (%s)", esp_err_to_name(err));
                esp_ota_abort(ota_handle);
                httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA write failed");
                return ESP_FAIL;
            }
            binary_file_length += received;
        }

        ESP_LOGI(TAG, "Written image length %" PRIu32 " of %" PRIu32, 
                 binary_file_length, content_length);
    }

    // Kết thúc OTA
    err = esp_ota_end(ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed (%s)!", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA end failed");
        return ESP_FAIL;
    }

    // Set boot partition
    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to set boot partition");
        return ESP_FAIL;
    }

    // Gửi response thành công
    const char* success_response = "{\"status\":\"success\",\"message\":\"OTA update complete\"}";
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, success_response, strlen(success_response));

    // Thông báo cho monitor task
    http_server_monitor_send_message(HTTP_MSG_OTA_UPDATE_SUCCESSFUL);

    // Schedule restart
    ESP_LOGI(TAG, "OTA update successful. Restarting in 5 seconds...");
    vTaskDelay(pdMS_TO_TICKS(5000));
    esp_restart();

    return ESP_OK;
}

esp_err_t http_server_OTA_status_handler(httpd_req_t *req)
{
	char otaJSON[100];

	ESP_LOGI(TAG, "OTAstatus requested");

	sprintf(otaJSON, "{\"ota_update_status\":%d,\"compile_time\":\"%s\",\"compile_date\":\"%s\"}", g_fw_update_status, __TIME__, __DATE__);

	httpd_resp_set_type(req, "application/json");
	httpd_resp_send(req, otaJSON, strlen(otaJSON));

	return ESP_OK;
}

static esp_err_t http_server_wifi_connect_json_handler(httpd_req_t *req)
{
	ESP_LOGI(TAG, "/wifiConnect.json requested");

	size_t len_ssid = 0, len_pass = 0;
	char *ssid_str = NULL, *pass_str = NULL;

	// Get SSID header
	len_ssid = httpd_req_get_hdr_value_len(req, "my-connect-ssid") + 1;
	if (len_ssid > 1)
	{
		ssid_str = malloc(len_ssid);
		if (httpd_req_get_hdr_value_str(req, "my-connect-ssid", ssid_str, len_ssid) == ESP_OK)
		{
			ESP_LOGI(TAG, "http_server_wifi_connect_json_handler: Found header => my-connect-ssid: %s", ssid_str);
		}
	}

	// Get Password header
	len_pass = httpd_req_get_hdr_value_len(req, "my-connect-pwd") + 1;
	if (len_pass > 1)
	{
		pass_str = malloc(len_pass);
		if (httpd_req_get_hdr_value_str(req, "my-connect-pwd", pass_str, len_pass) == ESP_OK)
		{
			ESP_LOGI(TAG, "http_server_wifi_connect_json_handler: Found header => my-connect-pwd: %s", pass_str);
		}
	}

	// Update the Wifi networks configuration and let the wifi application know
	wifi_config_t* wifi_config = wifi_app_get_wifi_config();
	memset(wifi_config, 0x00, sizeof(wifi_config_t));
	memcpy(wifi_config->sta.ssid, ssid_str, len_ssid);
	memcpy(wifi_config->sta.password, pass_str, len_pass);
	wifi_app_send_message(WIFI_APP_MSG_CONNECTING_FROM_HTTP_SERVER);

	free(ssid_str);
	free(pass_str);

	return ESP_OK;
}

static esp_err_t http_server_wifi_connect_status_json_handler(httpd_req_t *req)
{
	ESP_LOGI(TAG, "/wifiConnectStatus requested");

	char statusJSON[100];

	sprintf(statusJSON, "{\"wifi_connect_status\":%d}", g_wifi_connect_status);

	httpd_resp_set_type(req, "application/json");
	httpd_resp_send(req, statusJSON, strlen(statusJSON));

	return ESP_OK;
}

static esp_err_t http_server_get_wifi_connect_info_json_handler(httpd_req_t *req)
{
	ESP_LOGI(TAG, "/wifiConnectInfo.json requested");

	char ipInfoJSON[200];
	memset(ipInfoJSON, 0, sizeof(ipInfoJSON));

	char ip[IP4ADDR_STRLEN_MAX];
	char netmask[IP4ADDR_STRLEN_MAX];
	char gw[IP4ADDR_STRLEN_MAX];

	ESP_LOGI(TAG, "http_server_get_wifi_connect_info_json_handler: %d", g_wifi_connect_status);
	if (g_wifi_connect_status == HTTP_WIFI_STATUS_CONNECT_SUCCESS)
	{
		wifi_ap_record_t wifi_data;
		ESP_ERROR_CHECK(esp_wifi_sta_get_ap_info(&wifi_data));
		char *ssid = (char*)wifi_data.ssid;

		esp_netif_ip_info_t ip_info;
		ESP_ERROR_CHECK(esp_netif_get_ip_info(esp_netif_sta, &ip_info));
		esp_ip4addr_ntoa(&ip_info.ip, ip, IP4ADDR_STRLEN_MAX);
		esp_ip4addr_ntoa(&ip_info.netmask, netmask, IP4ADDR_STRLEN_MAX);
		esp_ip4addr_ntoa(&ip_info.gw, gw, IP4ADDR_STRLEN_MAX);

		sprintf(ipInfoJSON, "{\"ip\":\"%s\",\"netmask\":\"%s\",\"gw\":\"%s\",\"ap\":\"%s\"}", ip, netmask, gw, ssid);
	}

	httpd_resp_set_type(req, "application/json");
	httpd_resp_send(req, ipInfoJSON, strlen(ipInfoJSON));

	return ESP_OK;
}

static esp_err_t http_server_wifi_disconnect_json_handler(httpd_req_t *req)
{
	ESP_LOGI(TAG, "wifiDisconect.json requested");

	wifi_app_send_message(WIFI_APP_MSG_USER_REQUESTED_STA_DISCONNECT);

	return ESP_OK;
}

static void http_server_fw_update_reset_timer(void)
{
	if (g_fw_update_status == OTA_UPDATE_SUCCESSFUL)
	{
		ESP_LOGI(TAG, "http_server_fw_update_reset_timer: FW updated successful starting FW update reset timer");

		// Give the web page a chance to receive an acknowledge back and initialize the timer
		ESP_ERROR_CHECK(esp_timer_create(&fw_update_reset_args, &fw_update_reset));
		ESP_ERROR_CHECK(esp_timer_start_once(fw_update_reset, 8000000));
	}
	else
	{
		ESP_LOGI(TAG, "http_server_fw_update_reset_timer: FW update unsuccessful");
	}
}

static esp_err_t http_server_antenna_config_handler(httpd_req_t *req)
{
    char buf[512];
    cJSON *root = NULL;

    // Handle GET request
    if (req->method == HTTP_GET) {
        ESP_LOGI(TAG, "Processing GET request for antenna config");
        
        root = cJSON_CreateObject();
        
        // Đọc cấu hình hiện tại
        antenna_config_t current_config;
        if (app_nvs_load_antenna_config(&current_config) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to load antenna config");
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to load config");
            return ESP_FAIL;
        }

        // Create JSON response
        cJSON_AddNumberToObject(root, "power", current_config.power);
        cJSON *antennas = cJSON_CreateArray();
        for (int i = 0; i < MAX_ANTENNA_COUNT; i++) {
            cJSON_AddItemToArray(antennas, cJSON_CreateBool(current_config.antennas[i]));
        }
        cJSON_AddItemToObject(root, "antennas", antennas);

        char *json_str = cJSON_PrintUnformatted(root);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, json_str, strlen(json_str));

        free(json_str);
        cJSON_Delete(root);
        return ESP_OK;
    }

    // Handle POST request
    if (req->method == HTTP_POST) {
        ESP_LOGI(TAG, "Processing POST request for antenna config");
        
        // Đọc dữ liệu từ request
        int ret = httpd_req_recv(req, buf, sizeof(buf));
        if (ret <= 0) {
            ESP_LOGE(TAG, "Failed to receive POST data");
            return ESP_FAIL;
        }
        buf[ret] = '\0';
        
        // Parse JSON
        root = cJSON_Parse(buf);
        if (root == NULL) {
            ESP_LOGE(TAG, "Failed to parse JSON");
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
            return ESP_FAIL;
        }

        // Cập nhật cấu hình
        antenna_config_t new_config = {0};
        
        // Đọc power level
        cJSON *power = cJSON_GetObjectItem(root, "power");
        if (power) {
            new_config.power = power->valueint;
        }

        // Đọc trạng thái antenna
        cJSON *antennas = cJSON_GetObjectItem(root, "antennas");
        if (antennas) {
            for (int i = 0; i < MAX_ANTENNA_COUNT && i < cJSON_GetArraySize(antennas); i++) {
                cJSON *antenna = cJSON_GetArrayItem(antennas, i);
                if (antenna) {
                    new_config.antennas[i] = cJSON_IsTrue(antenna);
                }
            }
        }

        // Lưu cấu hình vào NVS
        esp_err_t err = app_nvs_save_antenna_config(&new_config);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to save antenna config");
            cJSON_Delete(root);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save config");
            return ESP_FAIL;
        }

        // Gửi response thành công
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"status\":\"ok\"}", strlen("{\"status\":\"ok\"}"));
        
        cJSON_Delete(root);
        ESP_LOGI(TAG, "Antenna configuration saved successfully");
        return ESP_OK;
    }

    return ESP_FAIL;
}

static esp_err_t http_server_protocol_config_handler(httpd_req_t *req)
{
    char buf[512];
    cJSON *root = NULL;
    
    // Handle GET request
    if (req->method == HTTP_GET) {
        // Load current config
        if (app_nvs_load_protocol_config(&g_protocol_config) != ESP_OK) {
            ESP_LOGE(TAG, "Failed to load protocol config");
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to load config");
            return ESP_FAIL;
        }
        
        // Create JSON response
        root = cJSON_CreateObject();
        
        // Add protocol type
        const char* protocol_str = (g_protocol_config.type == PROTOCOL_WEBSOCKET) ? "websocket" : "ble_hid";
        cJSON_AddStringToObject(root, "protocol", protocol_str);
        
        // Always include both configs in response
        cJSON *websocket = cJSON_CreateObject();
        cJSON_AddStringToObject(websocket, "url", g_protocol_config.websocket.url);
        cJSON_AddNumberToObject(websocket, "port", g_protocol_config.websocket.port);
        cJSON_AddNumberToObject(websocket, "max_clients", g_protocol_config.websocket.max_clients);
        cJSON_AddItemToObject(root, "websocket", websocket);
        
        cJSON *ble_hid = cJSON_CreateObject();
        cJSON_AddStringToObject(ble_hid, "device_name", g_protocol_config.ble_hid.device_name);
        cJSON_AddStringToObject(ble_hid, "pin_code", g_protocol_config.ble_hid.pin_code);
        cJSON_AddItemToObject(root, "ble_hid", ble_hid);
        
        ESP_LOGI(TAG, "Sending protocol config response");
        
        char *json_str = cJSON_PrintUnformatted(root);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, json_str, strlen(json_str));
        
        free(json_str);
        cJSON_Delete(root);
        return ESP_OK;
    }
    
    // Handle POST request
    if (req->method == HTTP_POST) {
        int ret = httpd_req_recv(req, buf, sizeof(buf));
        if (ret <= 0) {
            return ESP_FAIL;
        }
        buf[ret] = '\0';
        
        // Debug log
        ESP_LOGI(TAG, "Received POST data: %s", buf);
        
        root = cJSON_Parse(buf);
        if (root == NULL) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
            return ESP_FAIL;
        }
        
        // Parse protocol type
        cJSON *protocol = cJSON_GetObjectItem(root, "protocol");
        if (protocol && protocol->valuestring) {
            ESP_LOGI(TAG, "Setting protocol to: %s", protocol->valuestring);
            
            if (strcmp(protocol->valuestring, "websocket") == 0) {
                g_protocol_config.type = PROTOCOL_WEBSOCKET;
                
                cJSON *websocket = cJSON_GetObjectItem(root, "websocket");
                if (websocket) {
                    cJSON *url = cJSON_GetObjectItem(websocket, "url");
                    cJSON *port = cJSON_GetObjectItem(websocket, "port");
                    cJSON *max_clients = cJSON_GetObjectItem(websocket, "max_clients");
                    
                    if (url && url->valuestring) {
                        strncpy(g_protocol_config.websocket.url, url->valuestring, 
                                sizeof(g_protocol_config.websocket.url) - 1);
                    }
                    if (port && port->valueint) {
                        g_protocol_config.websocket.port = port->valueint;
                    }
                    if (max_clients && max_clients->valueint) {
                        g_protocol_config.websocket.max_clients = max_clients->valueint;
                    }
                }
            } else if (strcmp(protocol->valuestring, "ble_hid") == 0) {
                g_protocol_config.type = PROTOCOL_BLE_HID;
                
                cJSON *ble_hid = cJSON_GetObjectItem(root, "ble_hid");
                if (ble_hid) {
                    cJSON *device_name = cJSON_GetObjectItem(ble_hid, "device_name");
                    cJSON *pin_code = cJSON_GetObjectItem(ble_hid, "pin_code");
                    
                    if (device_name && device_name->valuestring) {
                        strncpy(g_protocol_config.ble_hid.device_name, device_name->valuestring, 
                                sizeof(g_protocol_config.ble_hid.device_name) - 1);
                        ESP_LOGI(TAG, "Set BLE device name: %s", g_protocol_config.ble_hid.device_name);
                    }
                    if (pin_code && pin_code->valuestring) {
                        strncpy(g_protocol_config.ble_hid.pin_code, pin_code->valuestring, 
                                sizeof(g_protocol_config.ble_hid.pin_code) - 1);
                        ESP_LOGI(TAG, "Set BLE PIN: %s", g_protocol_config.ble_hid.pin_code);
                    }
                }
            }
        }
        
        cJSON_Delete(root);
        
        // Save to NVS
        esp_err_t err = app_nvs_save_protocol_config(&g_protocol_config);
        if (err != ESP_OK) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to save config");
            return ESP_FAIL;
        }
        
        // Send success response
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"status\":\"ok\"}", 15);
        return ESP_OK;
    }
    
    return ESP_FAIL;
}

static void http_server_monitor(void *parameter)
{
	http_server_queue_message_t msg;

	for (;;)
	{
		if (xQueueReceive(http_server_monitor_queue_handle, &msg, portMAX_DELAY))
		{
			switch (msg.msgID)
			{
				case HTTP_MSG_WIFI_CONNECT_INIT:
					ESP_LOGI(TAG, "HTTP_MSG_WIFI_CONNECT_INIT");
					// g_wifi_connect_status = HTTP_WIFI_STATUS_CONNECTING;
					break;

				case HTTP_MSG_WIFI_CONNECT_SUCCESS:
					ESP_LOGI(TAG, "HTTP_MSG_WIFI_CONNECT_SUCCESS");
					g_wifi_connect_status = HTTP_WIFI_STATUS_CONNECT_SUCCESS;
					break;

				case HTTP_MSG_WIFI_CONNECT_FAIL:
					ESP_LOGI(TAG, "HTTP_MSG_WIFI_CONNECT_FAIL");
					g_wifi_connect_status = HTTP_WIFI_STATUS_CONNECT_FAILED;
					break;

				case HTTP_MSG_WIFI_USER_DISCONNECT:
				    ESP_LOGI(TAG, "HTTP_MSG_WIFI_USER_DISCONNECT");
					g_wifi_connect_status = HTTP_WIFI_STATUS_DISCONNECTED;
					break;

				case HTTP_MSG_OTA_UPDATE_SUCCESSFUL:
					ESP_LOGI(TAG, "HTTP_MSG_OTA_UPDATE_SUCCESSFUL");
					g_fw_update_status = OTA_UPDATE_SUCCESSFUL;
					http_server_fw_update_reset_timer();

					break;

				case HTTP_MSG_OTA_UPDATE_FAILED:
					ESP_LOGI(TAG, "HTTP_MSG_OTA_UPDATE_FAILED");
					g_fw_update_status = OTA_UPDATE_FAILED;

					break;

				default:
					break;
			}
		}
	}
}

static void send_ping(void *arg)
{
    struct async_resp_arg *resp_arg = arg;
    httpd_handle_t hd = resp_arg->hd;
    int fd = resp_arg->fd;
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.payload = NULL;
    ws_pkt.len = 0;
    ws_pkt.type = HTTPD_WS_TYPE_PING;

    httpd_ws_send_frame_async(hd, fd, &ws_pkt);
    free(resp_arg);
}

bool client_not_alive_cb(wss_keep_alive_t h, int fd)
{
    static int retry_count[CONFIG_LWIP_MAX_SOCKETS] = {0};
    
    ESP_LOGW(TAG, "Client not alive check for fd %d, retry count: %d", fd, retry_count[fd]);
    
    if (retry_count[fd] < MAX_RETRY) {
        retry_count[fd]++;
        ESP_LOGI(TAG, "Retrying connection for fd %d, attempt %d/%d", 
                 fd, retry_count[fd], MAX_RETRY);
        return true; // Give it another chance
    }
    
    ESP_LOGE(TAG, "Client not alive, closing fd %d after %d retries", fd, retry_count[fd]);
    retry_count[fd] = 0; // Reset counter
    
    httpd_handle_t hd = wss_keep_alive_get_user_ctx(h);
    if (hd) {
        // Xóa client khỏi keep-alive list trước
        wss_keep_alive_remove_client(h, fd);
        // Sau đó đóng kết nối
        httpd_sess_trigger_close(hd, fd);
    }
    
    return false;  // Không tiếp tục theo dõi client này nữa
}

bool check_client_alive_cb(wss_keep_alive_t h, int fd)
{
    ESP_LOGD(TAG, "Checking if client (fd=%d) is alive", fd);
    
    struct async_resp_arg *resp_arg = malloc(sizeof(struct async_resp_arg));
    if (resp_arg == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory");
        return false;
    }
    
    resp_arg->hd = wss_keep_alive_get_user_ctx(h);
    resp_arg->fd = fd;

    if (httpd_queue_work(resp_arg->hd, send_ping, resp_arg) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to queue ping work for fd %d", fd);
        free(resp_arg);
        return false;
    }
    
    return true;
}

esp_err_t wss_open_fd(httpd_handle_t hd, int sockfd)
{
    ESP_LOGI(TAG, "New client connected %d", sockfd);
    wss_keep_alive_t h = httpd_get_global_user_ctx(hd);
    return wss_keep_alive_add_client(h, sockfd);
}

void wss_close_fd(httpd_handle_t hd, int sockfd)
{
    ESP_LOGI(TAG, "Client disconnected %d", sockfd);
    wss_keep_alive_t h = httpd_get_global_user_ctx(hd);
    wss_keep_alive_remove_client(h, sockfd);
    close(sockfd);
}

static httpd_handle_t start_wss_echo_server(void)
{
    // Prepare keep-alive engine
    wss_keep_alive_config_t keep_alive_config = KEEP_ALIVE_CONFIG_DEFAULT();
    keep_alive_config.max_clients = max_clients;
    keep_alive_config.keep_alive_period_ms = KEEPALIVE_INTERVAL * 1000;  
    keep_alive_config.not_alive_after_ms = KEEPALIVE_TIMEOUT * 1000;
    keep_alive_config.client_not_alive_cb = client_not_alive_cb;
    keep_alive_config.check_client_alive_cb = check_client_alive_cb;
    wss_keep_alive_t keep_alive = wss_keep_alive_start(&keep_alive_config);

    // Start the httpd server
    httpd_handle_t server = NULL;
    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    
    // Điều chỉnh các thông số server
    conf.httpd.max_open_sockets = max_clients;
    conf.httpd.lru_purge_enable = true;  // Enable LRU purge
    conf.httpd.recv_wait_timeout = 30;   // 30 seconds timeout
    conf.httpd.send_wait_timeout = 30;   // 30 seconds timeout
    conf.httpd.global_user_ctx = keep_alive;
    conf.httpd.global_user_ctx_free_fn = NULL;
    conf.httpd.open_fn = wss_open_fd;
    conf.httpd.close_fn = wss_close_fd;

	conf.httpd.stack_size = 8192;
	conf.httpd.max_uri_handlers = 20;

    extern const unsigned char servercert_start[] asm("_binary_servercert_pem_start");
    extern const unsigned char servercert_end[]   asm("_binary_servercert_pem_end");
    conf.servercert = servercert_start;
    conf.servercert_len = servercert_end - servercert_start;

    extern const unsigned char prvtkey_pem_start[] asm("_binary_prvtkey_pem_start");
    extern const unsigned char prvtkey_pem_end[]   asm("_binary_prvtkey_pem_end");
    conf.prvtkey_pem = prvtkey_pem_start;
    conf.prvtkey_len = prvtkey_pem_end - prvtkey_pem_start;

	// conf.transport_mode = HTTPD_SSL_TRANSPORT_INSECURE;
	conf.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
	conf.session_tickets = false;

    esp_err_t ret = httpd_ssl_start(&server, &conf);
    if (ESP_OK != ret) {
        ESP_LOGI(TAG, "Error starting server!");
        return NULL;
    }

    // Set URI handlers
    ESP_LOGI(TAG, "Registering URI handlers");
    
	static const httpd_uri_t ws = {
			.uri        = "/ws",
			.method     = HTTP_GET,
			.handler    = ws_handler,
			.user_ctx   = NULL,
			.is_websocket = true,
			.handle_ws_control_frames = true
	};
	httpd_register_uri_handler(server, &ws);

	httpd_uri_t jquery_js = {
        .uri = "/jquery-3.3.1.min.js",
        .method = HTTP_GET,
        .handler = http_server_jquery_handler,
        .user_ctx = NULL,
		.is_websocket = true,
        .handle_ws_control_frames = true
	};
	httpd_register_uri_handler(server, &jquery_js);

	httpd_uri_t index_html = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = http_server_index_html_handler,
        .user_ctx = NULL,
		.is_websocket = true,
        .handle_ws_control_frames = true
	};
    httpd_register_uri_handler(server, &index_html);

	httpd_uri_t app_css = {
        .uri = "/app.css",
        .method = HTTP_GET,
        .handler = http_server_app_css_handler,
        .user_ctx = NULL,
		.is_websocket = true,
        .handle_ws_control_frames = true
	};
    httpd_register_uri_handler(server, &app_css);

	httpd_uri_t app_js = {
        .uri = "/app.js",
        .method = HTTP_GET,
        .handler = http_server_app_js_handler,
        .user_ctx = NULL,
		.is_websocket = true,
        .handle_ws_control_frames = true
	};
    httpd_register_uri_handler(server, &app_js);

	httpd_uri_t favicon_ico = {
        .uri = "/favicon.ico",
        .method = HTTP_GET,
        .handler = http_server_favicon_ico_handler,
        .user_ctx = NULL,
		.is_websocket = true,
        .handle_ws_control_frames = true
	};
    httpd_register_uri_handler(server, &favicon_ico);

	httpd_uri_t wifi_connect_json = {
		.uri = "/wifiConnect.json",
		.method = HTTP_POST,
		.handler = http_server_wifi_connect_json_handler,
		.user_ctx = NULL,
		.is_websocket = true,
        .handle_ws_control_frames = true
	};
	httpd_register_uri_handler(server, &wifi_connect_json);

	httpd_uri_t wifi_connect_status_json = {
				.uri = "/wifiConnectStatus",
				.method = HTTP_POST,
				.handler = http_server_wifi_connect_status_json_handler,
				.user_ctx = NULL
		};
	httpd_register_uri_handler(server, &wifi_connect_status_json);

	httpd_uri_t wifi_connect_info_json = {
		.uri = "/wifiConnectInfo.json",
		.method = HTTP_GET,
		.handler = http_server_get_wifi_connect_info_json_handler,
		.user_ctx = NULL,
		.is_websocket = true,
        .handle_ws_control_frames = true
	};
	httpd_register_uri_handler(server, &wifi_connect_info_json);

	httpd_uri_t wifi_disconnect_json = {
		.uri = "/wifiDisconnect.json",
		.method = HTTP_DELETE,
		.handler = http_server_wifi_disconnect_json_handler,
		.user_ctx = NULL,
		.is_websocket = true,
        .handle_ws_control_frames = true
	};
	httpd_register_uri_handler(server, &wifi_disconnect_json);

	httpd_uri_t OTA_status = {
			.uri = "/OTAstatus",
			.method = HTTP_POST,
			.handler = http_server_OTA_status_handler,
			.user_ctx = NULL
	};
	httpd_register_uri_handler(server, &OTA_status);

	httpd_uri_t antenna_config = {
		.uri = "/antennaConfig.json",
		.method = HTTP_GET,
		.handler = http_server_antenna_config_handler,
		.user_ctx = NULL
	};
	httpd_register_uri_handler(server, &antenna_config);

	httpd_uri_t antenna_config_post = {
		.uri = "/antennaConfig.json",
		.method = HTTP_POST,
		.handler = http_server_antenna_config_handler,
		.user_ctx = NULL
	};
	httpd_register_uri_handler(server, &antenna_config_post);

	httpd_uri_t protocol_config = {
		.uri = "/protocolConfig.json",
		.method = HTTP_GET,
		.handler = http_server_protocol_config_handler,
		.user_ctx = NULL
	};
	httpd_register_uri_handler(server, &protocol_config);

	httpd_uri_t protocol_config_post = {
		.uri = "/protocolConfig.json",
		.method = HTTP_POST,
		.handler = http_server_protocol_config_handler,
		.user_ctx = NULL
	};
	httpd_register_uri_handler(server, &protocol_config_post);

	httpd_uri_t reboot_uri = {
		.uri = "/reboot",
		.method = HTTP_POST,
		.handler = http_server_reboot_handler,
		.user_ctx = NULL
	};
	httpd_register_uri_handler(server, &reboot_uri);

	httpd_uri_t ota_update = {
		.uri       = "/OTAupdate",
		.method    = HTTP_POST,
		.handler   = http_server_OTA_update_handler,
		.user_ctx  = NULL
	};

	// httpd_uri_t firmware_info = {
	// 	.uri       = "/firmware-info",
	// 	.method    = HTTP_GET,
	// 	.handler   = http_server_firmware_info_handler,
	// 	.user_ctx  = NULL
	// };

	httpd_register_uri_handler(server, &ota_update);
	// httpd_register_uri_handler(server, &firmware_info);

    wss_keep_alive_set_user_ctx(keep_alive, server);

	xTaskCreate(
			&http_server_monitor, 
			"http_server_monitor", 
			HTTP_SERVER_MONITOR_STACK_SIZE, 
			NULL, 
			HTTP_SERVER_MONITOR_PRIORITY, 
			&task_http_server_monitor);

	http_server_monitor_queue_handle = xQueueCreate(3, sizeof(http_server_queue_message_t));

	return server;
}

static esp_err_t stop_wss_echo_server(httpd_handle_t server)
{
    // Stop keep alive thread
    wss_keep_alive_stop(httpd_get_global_user_ctx(server));
    // Stop the httpd server
    return httpd_ssl_stop(server);
}


void http_server_start(void)
{
	if (http_server_handle == NULL)
	{
		http_server_handle = start_wss_echo_server();
	}
}

void http_server_stop(void)
{
	if (http_server_handle)
	{
		stop_wss_echo_server(http_server_handle);
		ESP_LOGI(TAG, "http_server_stop: stopping HTTP server");
		http_server_handle = NULL;
	}
	if (task_http_server_monitor)
	{
		vTaskDelete(task_http_server_monitor);
		ESP_LOGI(TAG, "http_server_stop: stopping HTTP server monitor");
		task_http_server_monitor = NULL;
	}
}

BaseType_t http_server_monitor_send_message(http_server_message_e msgID)
{
	http_server_queue_message_t msg;
	msg.msgID = msgID;
	return xQueueSend(http_server_monitor_queue_handle, &msg, portMAX_DELAY);
}

void http_server_fw_update_reset_callback(void *arg)
{
	ESP_LOGI(TAG, "http_server_fw_update_reset_callback: Timer timed-out, restarting the device");
	esp_restart();
}


static void send_json(void *arg)
{
    struct async_resp_arg *resp_arg = arg;
    httpd_handle_t hd = resp_arg->hd;
    int fd = resp_arg->fd;
    const char* json_data = (const char*)resp_arg->data;
    // ESP_LOGI(TAG, "Sending JSON: %s", json_data);
    httpd_ws_frame_t ws_pkt;
    memset(&ws_pkt, 0, sizeof(httpd_ws_frame_t));
    ws_pkt.payload = (uint8_t*)json_data;
    ws_pkt.len = strlen(json_data);
    ws_pkt.type = HTTPD_WS_TYPE_TEXT;

    httpd_ws_send_frame_async(hd, fd, &ws_pkt);
    free(resp_arg->data); // Free the JSON string
    free(resp_arg);
}

// Gửi JSON cho một client cụ thể
esp_err_t wss_server_send_json_to_client(int client_fd, const char* json_data) 
{
    if (http_server_handle == NULL) {
        ESP_LOGE(TAG, "Server handle is NULL");
        return ESP_FAIL;
    }

    struct async_resp_arg *resp_arg = malloc(sizeof(struct async_resp_arg));
    if (resp_arg == NULL) {
        return ESP_ERR_NO_MEM;
    }
    
    char* json_copy = strdup(json_data);
    if (json_copy == NULL) {
        free(resp_arg);
        return ESP_ERR_NO_MEM;
    }

    resp_arg->hd = http_server_handle;
    resp_arg->fd = client_fd;
    resp_arg->data = json_copy;

    if (httpd_queue_work(http_server_handle, send_json, resp_arg) != ESP_OK) {
        free(json_copy);
        free(resp_arg);
        return ESP_FAIL;
    }
    
    return ESP_OK;
}

// Broadcast JSON cho tất cả clients
esp_err_t wss_server_broadcast_json(const char* json_data)
{
    if (http_server_handle == NULL) {
        ESP_LOGE(TAG, "Server handle is NULL");
        return ESP_FAIL;
    }

    size_t clients = max_clients;
    int client_fds[max_clients];
    
    if (httpd_get_client_list(http_server_handle, &clients, client_fds) != ESP_OK) {
        ESP_LOGE(TAG, "httpd_get_client_list failed!");
        return ESP_FAIL;
    }
    
    for (size_t i = 0; i < clients; ++i) {
        int sock = client_fds[i];
        if (httpd_ws_get_fd_info(http_server_handle, sock) == HTTPD_WS_CLIENT_WEBSOCKET) {
            ESP_LOGI(TAG, "Sending to client (fd=%d)", sock);
            wss_server_send_json_to_client(sock, json_data);
        }
    }
    
    return ESP_OK;
}

static esp_err_t http_server_reboot_handler(httpd_req_t *req)
{
    if (req->method == HTTP_POST) {
        ESP_LOGI(TAG, "Processing reboot request");
        
        // Send response before reboot
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"status\":\"ok\"}", strlen("{\"status\":\"ok\"}"));
        
        // Delay để đảm bảo response được gửi
        vTaskDelay(pdMS_TO_TICKS(100));
        
        // Reboot
        esp_restart();
        return ESP_OK;
    }
    return ESP_FAIL;
}

esp_err_t http_server_firmware_info_handler(httpd_req_t *req)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_app_desc_t app_desc;
    
    esp_err_t err = esp_ota_get_partition_description(running, &app_desc);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to get firmware info");
        return ESP_FAIL;
    }

    char json_response[200];
    snprintf(json_response, sizeof(json_response),
             "{\"version\":\"%s\",\"idf_ver\":\"%s\",\"project_name\":\"%s\",\"time\":\"%s\",\"date\":\"%s\"}",
             app_desc.version,
             app_desc.idf_ver,
             app_desc.project_name,
             app_desc.time,
             app_desc.date);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_response, strlen(json_response));

    return ESP_OK;
}

