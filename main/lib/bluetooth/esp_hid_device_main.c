/*
 * SPDX-FileCopyrightText: 2021-2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_bt.h"


#include "esp_bt_defs.h"
#if CONFIG_BT_BLE_ENABLED
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_gatt_defs.h"
#endif
#include "esp_bt_main.h"
#include "esp_bt_device.h"
#if CONFIG_BT_SDP_COMMON_ENABLED
#include "esp_sdp_api.h"
#endif /* CONFIG_BT_SDP_COMMON_ENABLED */

#include "esp_hidd.h"
#include "esp_hid_gap.h"

static const char *TAG = "HID_DEV_DEMO";
char device_name[64];
char pin_code[7];
typedef struct
{
    TaskHandle_t task_hdl;
    esp_hidd_dev_t *hid_dev;
    uint8_t protocol_mode;
    uint8_t *buffer;
} local_param_t;

#if CONFIG_BT_BLE_ENABLED || CONFIG_BT_NIMBLE_ENABLED
static local_param_t s_ble_hid_param = {0};

const unsigned char mediaReportMap[] = {
    0x05, 0x0C,        // Usage Page (Consumer)
    0x09, 0x01,        // Usage (Consumer Control)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x03,        //   Report ID (3)
    // 0x09, 0x02,        //   Usage (Numeric Key Pad)
    // 0xA1, 0x02,        //   Collection (Logical)
    // 0x05, 0x09,        //     Usage Page (Button)
    // 0x19, 0x01,        //     Usage Minimum (0x01)
    // 0x29, 0x0A,        //     Usage Maximum (0x0A)
    // 0x15, 0x01,        //     Logical Minimum (1)
    // 0x25, 0x0A,        //     Logical Maximum (10)
    // 0x75, 0x04,        //     Report Size (4)
    // 0x95, 0x01,        //     Report Count (1)
    // 0x81, 0x00,        //     Input (Data,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
    // 0xC0,              //   End Collection
    // 0x05, 0x0C,        //   Usage Page (Consumer)
    // 0x09, 0x86,        //   Usage (Channel)
    // 0x15, 0xFF,        //   Logical Minimum (-1)
    // 0x25, 0x01,        //   Logical Maximum (1)
    // 0x75, 0x02,        //   Report Size (2)
    // 0x95, 0x01,        //   Report Count (1)
    // 0x81, 0x46,        //   Input (Data,Var,Rel,No Wrap,Linear,Preferred State,Null State)
    // 0x09, 0xE9,        //   Usage (Volume Increment)
    // 0x09, 0xEA,        //   Usage (Volume Decrement)
    // 0x15, 0x00,        //   Logical Minimum (0)
    // 0x75, 0x01,        //   Report Size (1)
    // 0x95, 0x02,        //   Report Count (2)
    // 0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    // 0x09, 0xE2,        //   Usage (Mute)
    // 0x09, 0x30,        //   Usage (Power)
    // 0x09, 0x83,        //   Usage (Recall Last)
    // 0x09, 0x81,        //   Usage (Assign Selection)
    // 0x09, 0xB0,        //   Usage (Play)
    // 0x09, 0xB1,        //   Usage (Pause)
    // 0x09, 0xB2,        //   Usage (Record)
    // 0x09, 0xB3,        //   Usage (Fast Forward)
    // 0x09, 0xB4,        //   Usage (Rewind)
    // 0x09, 0xB5,        //   Usage (Scan Next Track)
    // 0x09, 0xB6,        //   Usage (Scan Previous Track)
    // 0x09, 0xB7,        //   Usage (Stop)
    // 0x15, 0x01,        //   Logical Minimum (1)
    // 0x25, 0x0C,        //   Logical Maximum (12)
    // 0x75, 0x04,        //   Report Size (4)
    // 0x95, 0x01,        //   Report Count (1)
    // 0x81, 0x00,        //   Input (Data,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
    
    // Thêm định nghĩa cho buffer lớn để truyền dữ liệu
    0x75, 0x08,        //   Report Size (8)
    0x96, 0xB9, 0x00,        //   Report Count (64) // Có thể tăng lên để có buffer lớn hơn
    0x81, 0x02,        //   Input (Data,Var,Abs)
    0xC0               // End Collection
};

static esp_hid_raw_report_map_t ble_report_maps[] = {
    {
        .data = mediaReportMap,
        .len = sizeof(mediaReportMap)
    }
};

static esp_hid_device_config_t ble_hid_config = {
    .vendor_id          = 0x16C0,
    .product_id         = 0x05DF,
    .version            = 0x0100,
    .device_name        = device_name,
    .manufacturer_name  = "Espressif",
    .serial_number      = "1234567890",
    .report_maps        = ble_report_maps,
    .report_maps_len    = 1
};

#define HID_CC_RPT_MUTE                 1
#define HID_CC_RPT_POWER                2
#define HID_CC_RPT_LAST                 3
#define HID_CC_RPT_ASSIGN_SEL           4
#define HID_CC_RPT_PLAY                 5
#define HID_CC_RPT_PAUSE                6
#define HID_CC_RPT_RECORD               7
#define HID_CC_RPT_FAST_FWD             8
#define HID_CC_RPT_REWIND               9
#define HID_CC_RPT_SCAN_NEXT_TRK        10
#define HID_CC_RPT_SCAN_PREV_TRK        11
#define HID_CC_RPT_STOP                 12

#define HID_CC_RPT_CHANNEL_UP           0x10
#define HID_CC_RPT_CHANNEL_DOWN         0x30
#define HID_CC_RPT_VOLUME_UP            0x40
#define HID_CC_RPT_VOLUME_DOWN          0x80

// HID Consumer Control report bitmasks
#define HID_CC_RPT_NUMERIC_BITS         0xF0
#define HID_CC_RPT_CHANNEL_BITS         0xCF
#define HID_CC_RPT_VOLUME_BITS          0x3F
#define HID_CC_RPT_BUTTON_BITS          0xF0
#define HID_CC_RPT_SELECTION_BITS       0xCF

// Macros for the HID Consumer Control 2-byte report
#define HID_CC_RPT_SET_NUMERIC(s, x)    (s)[0] &= HID_CC_RPT_NUMERIC_BITS;   (s)[0] = (x)
#define HID_CC_RPT_SET_CHANNEL(s, x)    (s)[0] &= HID_CC_RPT_CHANNEL_BITS;   (s)[0] |= ((x) & 0x03) << 4
#define HID_CC_RPT_SET_VOLUME_UP(s)     (s)[0] &= HID_CC_RPT_VOLUME_BITS;    (s)[0] |= 0x40
#define HID_CC_RPT_SET_VOLUME_DOWN(s)   (s)[0] &= HID_CC_RPT_VOLUME_BITS;    (s)[0] |= 0x80
#define HID_CC_RPT_SET_BUTTON(s, x)     (s)[1] &= HID_CC_RPT_BUTTON_BITS;    (s)[1] |= (x)
#define HID_CC_RPT_SET_SELECTION(s, x)  (s)[1] &= HID_CC_RPT_SELECTION_BITS; (s)[1] |= ((x) & 0x03) << 4

// HID Consumer Usage IDs (subset of the codes available in the USB HID Usage Tables spec)
#define HID_CONSUMER_POWER          48  // Power
#define HID_CONSUMER_RESET          49  // Reset
#define HID_CONSUMER_SLEEP          50  // Sleep

#define HID_CONSUMER_MENU           64  // Menu
#define HID_CONSUMER_SELECTION      128 // Selection
#define HID_CONSUMER_ASSIGN_SEL     129 // Assign Selection
#define HID_CONSUMER_MODE_STEP      130 // Mode Step
#define HID_CONSUMER_RECALL_LAST    131 // Recall Last
#define HID_CONSUMER_QUIT           148 // Quit
#define HID_CONSUMER_HELP           149 // Help
#define HID_CONSUMER_CHANNEL_UP     156 // Channel Increment
#define HID_CONSUMER_CHANNEL_DOWN   157 // Channel Decrement

#define HID_CONSUMER_PLAY           176 // Play
#define HID_CONSUMER_PAUSE          177 // Pause
#define HID_CONSUMER_RECORD         178 // Record
#define HID_CONSUMER_FAST_FORWARD   179 // Fast Forward
#define HID_CONSUMER_REWIND         180 // Rewind
#define HID_CONSUMER_SCAN_NEXT_TRK  181 // Scan Next Track
#define HID_CONSUMER_SCAN_PREV_TRK  182 // Scan Previous Track
#define HID_CONSUMER_STOP           183 // Stop
#define HID_CONSUMER_EJECT          184 // Eject
#define HID_CONSUMER_RANDOM_PLAY    185 // Random Play
#define HID_CONSUMER_SELECT_DISC    186 // Select Disk
#define HID_CONSUMER_ENTER_DISC     187 // Enter Disc
#define HID_CONSUMER_REPEAT         188 // Repeat
#define HID_CONSUMER_STOP_EJECT     204 // Stop/Eject
#define HID_CONSUMER_PLAY_PAUSE     205 // Play/Pause
#define HID_CONSUMER_PLAY_SKIP      206 // Play/Skip

#define HID_CONSUMER_VOLUME         224 // Volume
#define HID_CONSUMER_BALANCE        225 // Balance
#define HID_CONSUMER_MUTE           226 // Mute
#define HID_CONSUMER_BASS           227 // Bass
#define HID_CONSUMER_VOLUME_UP      233 // Volume Increment
#define HID_CONSUMER_VOLUME_DOWN    234 // Volume Decrement

#define HID_RPT_ID_CC_IN        3   // Consumer Control input report ID
#define HID_CC_IN_RPT_LEN       512   // Consumer Control input report Len
void esp_hidd_send_consumer_value(const char* json_string)
{
    // Check if HID device is initialized and connected
    if (s_ble_hid_param.hid_dev == NULL) {
        ESP_LOGE(TAG, "HID device not initialized");
        return;
    }

    if (!esp_hidd_dev_connected(s_ble_hid_param.hid_dev)) {
        ESP_LOGE(TAG, "HID device not connected");
        return;
    }

    // Initialize buffer with zeros
    uint8_t buffer[HID_CC_IN_RPT_LEN] = {0};
    
    // Copy the JSON string to the buffer
    size_t json_len = strlen(json_string);
    if (json_len >= HID_CC_IN_RPT_LEN) {
        ESP_LOGW(TAG, "JSON string too long, truncating to %d bytes", HID_CC_IN_RPT_LEN - 1);
        json_len = HID_CC_IN_RPT_LEN - 1;
    }
    // memcpy(buffer, json_string, json_len);
    
    // ESP_LOGI(TAG, "Sending JSON (length: %d): %s", json_len, json_string);
    
    // Send the buffer as HID input
    esp_err_t err = esp_hidd_dev_input_set(s_ble_hid_param.hid_dev, 0, HID_RPT_ID_CC_IN, json_string, json_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to send HID report: %s", esp_err_to_name(err));
    }
}

void ble_hid_task_shut_down(void)
{
    if (s_ble_hid_param.task_hdl) {
        vTaskDelete(s_ble_hid_param.task_hdl);
        s_ble_hid_param.task_hdl = NULL;
    }
}

static void ble_hidd_event_callback(void *handler_args, esp_event_base_t base, int32_t id, void *event_data)
{
    esp_hidd_event_t event = (esp_hidd_event_t)id;
    esp_hidd_event_data_t *param = (esp_hidd_event_data_t *)event_data;
    static const char *TAG = "HID_DEV_BLE";

    switch (event) {
    case ESP_HIDD_START_EVENT: {
        ESP_LOGI(TAG, "START");
        esp_hid_ble_gap_adv_start();
        break;
    }
    case ESP_HIDD_CONNECT_EVENT: {
        ESP_LOGI(TAG, "CONNECT");
        break;
    }
    case ESP_HIDD_PROTOCOL_MODE_EVENT: {
        ESP_LOGI(TAG, "PROTOCOL MODE[%u]: %s", param->protocol_mode.map_index, param->protocol_mode.protocol_mode ? "REPORT" : "BOOT");
        break;
    }
    case ESP_HIDD_CONTROL_EVENT: {
        ESP_LOGI(TAG, "CONTROL[%u]: %sSUSPEND", param->control.map_index, param->control.control ? "EXIT_" : "");
        if (param->control.control)
        {
            // exit suspend
            // ble_hid_task_start_up();
        } else {
            // suspend
            ble_hid_task_shut_down();
        }
    break;
    }
    case ESP_HIDD_OUTPUT_EVENT: {
        ESP_LOGI(TAG, "OUTPUT[%u]: %8s ID: %2u, Len: %d, Data:", param->output.map_index, esp_hid_usage_str(param->output.usage), param->output.report_id, param->output.length);
        ESP_LOG_BUFFER_HEX(TAG, param->output.data, param->output.length);
        break;
    }
    case ESP_HIDD_FEATURE_EVENT: {
        ESP_LOGI(TAG, "FEATURE[%u]: %8s ID: %2u, Len: %d, Data:", param->feature.map_index, esp_hid_usage_str(param->feature.usage), param->feature.report_id, param->feature.length);
        ESP_LOG_BUFFER_HEX(TAG, param->feature.data, param->feature.length);
        break;
    }
    case ESP_HIDD_DISCONNECT_EVENT: {
        ESP_LOGI(TAG, "DISCONNECT: %s", esp_hid_disconnect_reason_str(esp_hidd_dev_transport_get(param->disconnect.dev), param->disconnect.reason));
        ble_hid_task_shut_down();
        esp_hid_ble_gap_adv_start();
        break;
    }
    case ESP_HIDD_STOP_EVENT: {
        ESP_LOGI(TAG, "STOP");
        break;
    }
    default:
        break;
    }
    return;
}
#endif

void ble_hid_init(const char* device_name, uint32_t pin_code)
{
    strncpy(ble_hid_config.device_name, device_name, 6);
    esp_err_t ret;

    ESP_LOGI(TAG, "setting hid gap, mode:%d", HID_DEV_MODE);
    ret = esp_hid_gap_init(HID_DEV_MODE);
    ESP_ERROR_CHECK( ret );
    ret = esp_hid_ble_gap_adv_init(ESP_HID_APPEARANCE_GENERIC, device_name, pin_code);
    
    ESP_ERROR_CHECK( ret );
#if CONFIG_BT_BLE_ENABLED
    if ((ret = esp_ble_gatts_register_callback(esp_hidd_gatts_event_handler)) != ESP_OK) {
        ESP_LOGE(TAG, "GATTS register callback failed: %d", ret);
        return;
    }
#endif
    ESP_LOGI(TAG, "setting ble device");
    ESP_ERROR_CHECK(
        esp_hidd_dev_init(&ble_hid_config, ESP_HID_TRANSPORT_BLE, ble_hidd_event_callback, &s_ble_hid_param.hid_dev));

    // Configure security parameters
    esp_ble_auth_req_t auth_req = ESP_LE_AUTH_REQ_SC_MITM_BOND;
    esp_ble_io_cap_t iocap = ESP_IO_CAP_OUT;          // Display only
    uint8_t key_size = 16;
    uint8_t init_key = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK;
    uint8_t rsp_key = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK;
    uint32_t passkey = pin_code;
    uint8_t auth_option = ESP_BLE_ONLY_ACCEPT_SPECIFIED_AUTH_DISABLE;
    
    esp_ble_gap_set_security_param(ESP_BLE_SM_AUTHEN_REQ_MODE, &auth_req, sizeof(auth_req));
    esp_ble_gap_set_security_param(ESP_BLE_SM_IOCAP_MODE, &iocap, sizeof(iocap));
    esp_ble_gap_set_security_param(ESP_BLE_SM_MAX_KEY_SIZE, &key_size, sizeof(key_size));
    esp_ble_gap_set_security_param(ESP_BLE_SM_SET_INIT_KEY, &init_key, sizeof(init_key));
    esp_ble_gap_set_security_param(ESP_BLE_SM_SET_RSP_KEY, &rsp_key, sizeof(rsp_key));
    esp_ble_gap_set_security_param(ESP_BLE_SM_SET_STATIC_PASSKEY, &passkey, sizeof(passkey));
    esp_ble_gap_set_security_param(ESP_BLE_SM_ONLY_ACCEPT_SPECIFIED_SEC_AUTH, &auth_option, sizeof(auth_option));
}
