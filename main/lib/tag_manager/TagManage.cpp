/*
 * TagManager.cpp
 *
 *  Created on: Apr 19, 2024
 *      Author: HieuNM
 */

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "serial.hpp"
#include "stdlib.h"
#include "errno.h"
#include "unistd.h"
#include <map>
#include <vector>
#include <bits/stdc++.h>
#include <algorithm>
#include "typedefs.h"
#include <iterator>
#include <string>
#include "driver/gpio.h"
#include "cJSON.h"
#include "tag_list.hpp"
#include "app_nvs.h"
#include "button.h"
#include "http_server.h"
#include "TagManage.hpp"

#define PRESET_VALUE 0xFFFF
#define POLYNOMIAL  0x8408

#define INIT_1 {0x04, 0xFF, 0x21, 0x19, 0x95}
#define INIT_2 {0x04, 0x00, 0x21, 0xD9, 0x6A}
#define INIT_3 {0x04, 0x00, 0x51, 0x5E, 0x19}
#define INIT_4 {0x05, 0x00, 0x7F, 0x00, 0x7A, 0x1E}

#define READ_1 {0x09, 0x00, 0x01, 0x24, 0xFD, 0x00, 0x80, 0x32, 0xDC, 0xFB}
#define READ_2 {0x09, 0x00, 0x01, 0x24, 0xFD, 0x01, 0x80, 0x32, 0x00, 0xA1}

#define STOP {0x04, 0x00, 0x93, 0x40, 0xFC, 0x05, 0x00, 0x7F, 0xC5, 0xDB, 0x8F}

// #define TID_LEN 12
#define RSSI_LEN 1
#define PHASE_LEN 4
#define FREQ_LEN 3

typedef enum{
    INVENTORY_COMPLETED = 0x01,     // Operation completed, reader will report all inquired tags information to host
    INVENTORY_TIMEOUT = 0x02,       // Inventory  timeout, reader will report all the already inquired tags to host
    STATUS_03 = 0x03,               // For status = 0x03, reader is not able to response all the data in a single frame, further data will be transmitted in the following frames.
    STATUS_04 = 0x04,               // Reader only completed parts of the inventory but run out of memory space due to the amount of tags. Reader will report all the already inquired tags as well as this status value to host.
    STATUS_ANT_ERR = 0xF8,          // Antenna error detected, the current antenna might be disconnected.
    STATUS_26 = 0x26,               // After inventory, deliver statistic data of the last inventory process
}inventory_status_t;

antenna_config_t current_antenna_config = {
    .power = 10,  // Công suất mặc định = 10
    .antennas = {true, false, false, false,    // ant1 = true, còn lại false
                 false, false, false, false,
                 false, false, false, false,
                 false, false, false, false}
};

static const char *TASK_TAG = "RFID MANAGER";
std::unique_ptr<TagList> g_tagList = std::make_unique<TagList>();
bool_t is_inventory = false;

static bool setRFPower(uint8_t power);

static void stop_reader(void){
    uint8_t buffer[] = STOP;
    send_buffer(buffer, sizeof(buffer));
}

static void 
init_antenna_config(void) {
    esp_err_t err = app_nvs_load_antenna_config(&current_antenna_config);
    if (err != ESP_OK) {
        // Set defaults if loading fails
        current_antenna_config.power = 10;
        memset(current_antenna_config.antennas, false, sizeof(current_antenna_config.antennas));
        current_antenna_config.antennas[0] = true;
    }
}
static void EX100_init(void) {
	uint8_t buff[] = INIT_1;
	send_buffer(buff, sizeof(buff));

	vTaskDelay(30 / portTICK_PERIOD_MS);
	uint8_t buff1[] = INIT_2;
	send_buffer(buff1, sizeof(buff1));

	vTaskDelay(30 / portTICK_PERIOD_MS);
	uint8_t buff2[] = INIT_3;
	send_buffer(buff2, sizeof(buff2));

	vTaskDelay(30 / portTICK_PERIOD_MS);
	uint8_t buff3[] = INIT_4;
	send_buffer(buff3, sizeof(buff3));
}

static void tag_start_inventory(u8_t antenna){
    static bool_t target[16] = {0};

    if(antenna >= 16) {
        ESP_LOGE(TASK_TAG, "Invalid antenna number: %d", antenna);
        return;
    }
    uint8_t antenna_mask = 0x80 | antenna;  // 0x80 + antenna offset
    // Len + addr + cmd + Data + crc16

    uint8_t buffer[] = {
        0x09,               // Length
        0x00,               // Address
        0x01,               // Command
        0x24,               // Sub-command
        0xFD,               // Parameter
        target[antenna],    // 0 or 1 to inventory
        antenna_mask,       // Antenna selection
        0x32,               // Parameter
        0x00,               // CRC low (placeholder)
        0x00                // CRC high (placeholder)
    };
    // Calculate CRC

    uint16_t crc = uiCrc16Cal(buffer, sizeof(buffer) - 2);
    buffer[8] = crc & 0xFF;
    buffer[9] = (crc >> 8) & 0xFF;
    
    send_buffer(buffer, sizeof(buffer));
    ESP_LOGI(TASK_TAG, "Inventory antenna %d", antenna);
    target[antenna] = !target[antenna];
}

static void tag_manager_handle(void *arg)
{
	static bool_t state = 0;
	bool_t button_state;
    setRFPower(current_antenna_config.power);
	while(1) {
        if(is_inventory){
            // Step 1: Send command to reader
            tag_start_inventory(0);
            // Step 2: Wait for reader to respond
            vTaskDelay(1000 / portTICK_PERIOD_MS);

            // Step 3: Process the response from reader
            if(g_tagList->GetTotalReadCount() > 0){
                // TODO: Send data to server
                std::string jsonString = g_tagList->GetJsonString();
                g_tagList->Clear();
                // ESP_LOGI(TASK_TAG, "JSON string: %s", jsonString.c_str());
                wss_server_broadcast_json(jsonString.c_str());
                size_t heap_size = esp_get_free_heap_size();
                ESP_LOGW(TASK_TAG, "Heap Free: %u bytes", heap_size);
            }
        }
        vTaskDelay(10 / portTICK_PERIOD_MS);
	}
}

static void tag_manager_action(void *arg){
    for(;;){
        EventBits_t bits = xEventGroupWaitBits(
            button_event_group,
            BUTTON_1_TAP_BIT,
            pdTRUE,
            pdFALSE,
            portMAX_DELAY
        );
        if (bits & BUTTON_1_TAP_BIT) {
            is_inventory = !is_inventory;
        }
    }
}

void tag_manager_init(void) {
	esp_log_level_set(TASK_TAG, ESP_LOG_INFO);
    serial_init();
    vTaskDelay(100 / portTICK_PERIOD_MS);
    init_antenna_config();
    EX100_init();
    xTaskCreate(tag_manager_action, "Tag manager action", 1024, NULL, 2, NULL);
	xTaskCreate(tag_manager_handle, "Task manager handle", 1024*8, NULL, 2, NULL);
}

void tag_manager_process(u8_p payload, u8_t len){
    u8_t byCMD = payload[0];
    switch (byCMD)
    {
    case 0x01: //CMD 0x01
        uint8_t byStatus = payload[1];
        switch (byStatus)
        {
        case STATUS_03:
        {
            uint8_t byAntenna = payload[2];
            uint8_t byNumberEPCInMsg = payload[3];
            if(byNumberEPCInMsg == 0x00){
                // No tag found
                return;
            }
            else{
                // More tag found
                u8_t byOption;
                u16_t byOptionIndex = 4;
                for(u8_t i = 0; i < byNumberEPCInMsg; i++){
                    byOption = payload[byOptionIndex];
                    u8_t byLenEPC;
                    std::vector<u8_t> newTagEPC;
                    std::array<u8_t, TID_LEN> newTagTID;
                    bool_t isEnablePhaseAndFreq = (bool_t)(byOption & 0x40);

                    if(!(byOption & 0x80)){ //data block contains EPC or TID
                        byLenEPC = (byOption & 0x3F);
                        newTagEPC.resize(byLenEPC);
                        std::copy(payload + byOptionIndex + 1, payload + byOptionIndex + 1 + byLenEPC, newTagEPC.begin());
                    }
                    else { // data block contains EPC plus TID (FastID enabled).
                        byLenEPC = (byOption & 0x3F) - 12;
                        newTagEPC.resize(byLenEPC);
                        std::copy(payload + byOptionIndex + 1, payload + byOptionIndex + 1 + byLenEPC, newTagEPC.begin());
                        std::copy(payload + byOptionIndex + 1 + byLenEPC, payload + byOptionIndex + 1 + byLenEPC + TID_LEN, newTagTID.begin());
                    }
                    // printf("\nTagEPC:");
                    // for(const auto& element : newTagEPC){
                    //     printf("%X ", element);
                    // }
                    // printf("\nTagTID:");
                    // for(const auto& element : newTagTID){
                    //     printf("%X ", element);
                    // }
                    // printf("\n");
                    u8_t byRssi = payload[byOptionIndex + 1 + byLenEPC + TID_LEN];

                    u32_t phase = 0;
                    u32_t freq = 0;
                    if(isEnablePhaseAndFreq){
                        u8_t byPhase[PHASE_LEN] = {0};
                        u8_t byFreq[FREQ_LEN] = {0};
                        memcpy(&byPhase, payload + byOptionIndex + 1 + byLenEPC + TID_LEN + RSSI_LEN, sizeof(byPhase));
                        memcpy(&byFreq, payload + byOptionIndex + 1 + byLenEPC + TID_LEN + RSSI_LEN + PHASE_LEN, sizeof(byFreq));
                        phase = byPhase[0] << 24 | byPhase[1] << 16 | byPhase[2] << 8 | byPhase[3];
                        freq = byFreq[0] << 16 | byFreq[1] << 8 | byFreq[2];
                    }
                    else{
                        // ESP_LOGI(TASK_TAG, "Phase and freq is not enabled");
                    }
                    g_tagList->AddOrUpdateTag(newTagEPC, newTagTID, byAntenna, byRssi, phase, freq);
                }
            }
            break;
        }
        default:
            break;
        }
    }
}

std::string arrayToString(const std::array<u8_t, 12>& arr) {
    char str[36];

    for (size_t i = 0; i < arr.size(); ++i) {
        sprintf(&str[i*3], "%02X ", arr[i]);
    }
    return std::string(str);
}

unsigned int uiCrc16Cal(unsigned char const  * pucY, unsigned char ucX)
{
	unsigned char ucI,ucJ;
	unsigned short int  uiCrcValue = PRESET_VALUE;
   	for(ucI = 0; ucI < ucX; ucI++)
	   {
		   uiCrcValue = uiCrcValue ^ *(pucY + ucI);
	  	   for(ucJ = 0; ucJ < 8; ucJ++)
	   	  {
		 	if(uiCrcValue & 0x0001)
		   	{
		    	uiCrcValue = (uiCrcValue >> 1) ^ POLYNOMIAL;
		   	}
		 	else
		   	{
		    	uiCrcValue = (uiCrcValue >> 1);
		   	}
		}
 	}
	return uiCrcValue;
}

/**
 * Set RF power level for the reader
 * @param power Power level (0-10)
 * @return true if command was sent successfully
 */
static bool setRFPower(uint8_t power) {
    if (power > 30) return false; // Validate power level
    
    uint8_t cmd[] = {
        0x05,       // Length
        0x00,       // Address
        0x2F,       // Command
        power,      // Power level
        0x00,       // CRC low (placeholder)
        0x00        // CRC low (placeholder)
    };
    
    // Calculate CRC16 for the command (excluding CRC bytes)
    uint16_t crc = uiCrc16Cal(cmd, sizeof(cmd) - 2);
    
    // Add CRC bytes
    cmd[4] = crc & 0xFF;         // CRC low byte
    cmd[5] = (crc >> 8) & 0xFF;  // CRC high byte
    
    // Send command to UART/Serial
    return send_buffer(cmd, sizeof(cmd));
}