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
            // Xử lý text message
            ESP_LOGI(TAG, "Received text message: %s", (char*)ws_pkt.payload);
            // Có thể echo lại message cho client
            httpd_ws_frame_t ws_response = {
                .final = true,
                .fragmented = false,
                .type = HTTPD_WS_TYPE_TEXT,
                .payload = ws_pkt.payload,
                .len = ws_pkt.len
            };
            ret = httpd_ws_send_frame(req, &ws_response);
            if (ret != ESP_OK) {
                ESP_LOGE(TAG, "httpd_ws_send_frame failed with %d", ret);
            }
            break;
            
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

	char ota_buff[1024];
	int content_length = req->content_len;
	int content_received = 0;
	int recv_len;
	bool is_req_body_started = false;
	bool flash_successful = false;

	const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);

	do
	{
		// Read the data for the request
		if ((recv_len = httpd_req_recv(req, ota_buff, MIN(content_length, sizeof(ota_buff)))) < 0)
		{
			// Check if timeout occurred
			if (recv_len == HTTPD_SOCK_ERR_TIMEOUT)
			{
				ESP_LOGI(TAG, "http_server_OTA_update_handler: Socket Timeout");
				continue; ///> Retry receiving if timeout occurred
			}
			ESP_LOGI(TAG, "http_server_OTA_update_handler: OTA other Error %d", recv_len);
			return ESP_FAIL;
		}
		printf("http_server_OTA_update_handler: OTA RX: %d of %d\r", content_received, content_length);

		// Is this the first data we are receiving
		// If so, it will have the information in the header that we need.
		if (!is_req_body_started)
		{
			is_req_body_started = true;

			// Get the location of the .bin file content (remove the web form data)
			char *body_start_p = strstr(ota_buff, "\r\n\r\n") + 4;
			int body_part_len = recv_len - (body_start_p - ota_buff);

			printf("http_server_OTA_update_handler: OTA file size: %d\r\n", content_length);

			esp_err_t err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &ota_handle);
			if (err != ESP_OK)
			{
				printf("http_server_OTA_update_handler: Error with OTA begin, cancelling OTA\r\n");
				return ESP_FAIL;
			}
			else
			{
				printf("http_server_OTA_update_handler: Writing to partition subtype %d at offset 0x%lx\r\n", update_partition->subtype, update_partition->address);
			}

			// Write this first part of the data
			esp_ota_write(ota_handle, body_start_p, body_part_len);
			content_received += body_part_len;
		}
		else
		{
			// Write OTA data
			esp_ota_write(ota_handle, ota_buff, recv_len);
			content_received += recv_len;
		}

	} while (recv_len > 0 && content_received < content_length);

	if (esp_ota_end(ota_handle) == ESP_OK)
	{
		// Lets update the partition
		if (esp_ota_set_boot_partition(update_partition) == ESP_OK)
		{
			const esp_partition_t *boot_partition = esp_ota_get_boot_partition();
			ESP_LOGI(TAG, "http_server_OTA_update_handler: Next boot partition subtype %d at offset 0x%lx", boot_partition->subtype, boot_partition->address);
			flash_successful = true;
		}
		else
		{
			ESP_LOGI(TAG, "http_server_OTA_update_handler: FLASHED ERROR!!!");
		}
	}
	else
	{
		ESP_LOGI(TAG, "http_server_OTA_update_handler: esp_ota_end ERROR!!!");
	}

	// We won't update the global variables throughout the file, so send the message about the status
	if (flash_successful) { http_server_monitor_send_message(HTTP_MSG_OTA_UPDATE_SUCCESSFUL); } else { http_server_monitor_send_message(HTTP_MSG_OTA_UPDATE_FAILED); }

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
    char buf[200];
    char response[200];

    if (req->method == HTTP_GET) {
        // Tạo JSON response với cấu hình hiện tại
        snprintf(response, sizeof(response), 
                "{\"power\":%d,\"antennas\":[%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d]}", 
                current_antenna_config.power,
                current_antenna_config.antennas[0], current_antenna_config.antennas[1],
                current_antenna_config.antennas[2], current_antenna_config.antennas[3],
                current_antenna_config.antennas[4], current_antenna_config.antennas[5],
                current_antenna_config.antennas[6], current_antenna_config.antennas[7],
                current_antenna_config.antennas[8], current_antenna_config.antennas[9],
                current_antenna_config.antennas[10], current_antenna_config.antennas[11],
                current_antenna_config.antennas[12], current_antenna_config.antennas[13],
                current_antenna_config.antennas[14], current_antenna_config.antennas[15]);

		esp_err_t err = app_nvs_save_antenna_config(&current_antenna_config);
		if (err != ESP_OK) {
			const char *error_response = "{\"status\":\"error\",\"message\":\"Failed to save config\"}";
			httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, error_response);
			return ESP_FAIL;
		}

        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, response, strlen(response));
        return ESP_OK;
    }
    else if (req->method == HTTP_POST) {
        // Đọc JSON request
        int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
        if (ret <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                httpd_resp_send_408(req);
            }
            return ESP_FAIL;
        }
        buf[ret] = '\0';

        // Parse JSON
        cJSON *root = cJSON_Parse(buf);
        if (root == NULL) {
            const char *error_response = "{\"status\":\"error\",\"message\":\"Invalid JSON\"}";
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, error_response);
            return ESP_FAIL;
        }

        // Lấy giá trị power
        cJSON *power = cJSON_GetObjectItem(root, "power");
        if (cJSON_IsNumber(power)) {
            current_antenna_config.power = power->valueint;
        }

        // Lấy mảng trạng thái anten
        cJSON *antennas = cJSON_GetObjectItem(root, "antennas");
        if (cJSON_IsArray(antennas)) {
            int array_size = cJSON_GetArraySize(antennas);
            for (int i = 0; i < MIN(array_size, 16); i++) {
                cJSON *antenna = cJSON_GetArrayItem(antennas, i);
                if (cJSON_IsBool(antenna)) {
                    current_antenna_config.antennas[i] = cJSON_IsTrue(antenna);
                }
            }
        }

        // Áp dụng cấu hình vào phần cứng
        // TODO: Thêm code điều khiển phần cứng ở đây
        ESP_LOGI(TAG, "Applied antenna config - Power: %d", current_antenna_config.power);
        for (int i = 0; i < 16; i++) {
            ESP_LOGI(TAG, "Antenna %d: %s", i + 1, current_antenna_config.antennas[i] ? "ON" : "OFF");
        }

        cJSON_Delete(root);

        // Gửi response thành công
        const char *success_response = "{\"status\":\"success\"}";
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, success_response, strlen(success_response));
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
