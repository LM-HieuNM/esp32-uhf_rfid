/*
 * serial.cpp
 *
 *  Created on: Apr 19, 2024
 *      Author: HieuNM
 */


#include "serial.hpp"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "driver/uart.h"
#include "string.h"
#include "driver/gpio.h"
#include "queue"
#include "freertos/semphr.h"
#include <algorithm>
#include <iterator>
#include "packet.hpp"
#include "TagManage.hpp"
static const int RX_BUF_SIZE = 1024;
#define MAX_PACKET_SIZE 64
#define READER_ADDRESS 0x00

#define TXD_PIN (GPIO_NUM_7)
#define RXD_PIN (GPIO_NUM_6)

typedef struct {
    uint8_t* data;
    uint16_t length;
} uart_data_t;

typedef enum {
	PARSE_IDLE,
	PARSE_START,
	PARSE_PROGRESSING,
	PARSE_SUCCESS,
	PARSE_FAIL,
}parse_progress_t;

SemaphoreHandle_t mutex;
QueueHandle_t rxQueue;
RecvState_t m_enRecvState = FRS_LENGTH;
Packet_t ex10_packet;

static const char *TAG = "serial";

static void parse_data(uint8_t byData, bool_t is_data_new);


int send_buffer(const uint8_t* data, uint16_t length){
	const int txBytes = uart_write_bytes(UART_NUM_1, data, length);
	return txBytes;
}
int sendData(const char* logName, const char* data)
{
    const int len = strlen(data);
    const int txBytes = uart_write_bytes(UART_NUM_1, data, len);
    return txBytes;
}

static void serialParse_task(void *arg)
{
    bool_t is_data_new = false;
    uart_data_t uart_data;
    while (1) {
        if(xQueueReceive(rxQueue, &uart_data, portMAX_DELAY) == pdTRUE) {
            ESP_LOGI(TAG, "Recv %d bytes", uart_data.length);
            is_data_new = true;
            for(int i = 0; i < uart_data.length; i++) {
                parse_data(uart_data.data[i], is_data_new);
                is_data_new = false;
            }
            free(uart_data.data);
        }
    }
}

static void rx_task(void *arg)
{
	uint8_t* data = (uint8_t*) malloc(RX_BUF_SIZE+1);
    while (1) {
		uint16_t rxBytes = uart_read_bytes(UART_NUM_1, data, RX_BUF_SIZE, 50 / portTICK_PERIOD_MS);
		if(rxBytes > 0) {
			uint8_t* buffer = (uint8_t*)malloc(rxBytes);
			memcpy(buffer, data, rxBytes);
			
			uart_data_t uart_data = {
				.data = buffer,
				.length = rxBytes
			};
			
			if (xQueueSend(rxQueue, &uart_data, pdMS_TO_TICKS(100)) != pdTRUE) {
				free(buffer);
				ESP_LOGE(TAG, "Failed to send to queue");
			}
		}
		vTaskDelay(5 / portTICK_PERIOD_MS);
    }
    free(data);
}


void serial_init(void) {
    const uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    // We won't use a buffer for sending data.
    uart_driver_install(UART_NUM_1, RX_BUF_SIZE * 2, 0, 0, NULL, 0);
    uart_param_config(UART_NUM_1, &uart_config);
    uart_set_pin(UART_NUM_1, TXD_PIN, RXD_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    esp_log_level_set(TAG, ESP_LOG_DEBUG);

    rxQueue = xQueueCreate(32, sizeof(uart_data_t));

    if( rxQueue == NULL )
    {

    }
    mutex = xSemaphoreCreateMutex();
    if (mutex == NULL) {
    }
    else{
    	xSemaphoreGive(mutex);
    }

    xTaskCreate(serialParse_task, "Task Parse data serial", 1024*2, NULL, 2, NULL);
    xTaskCreate(rx_task, "Task Uart RX", 1024*2, NULL, 2, NULL);
}


bool_t arraysEqual(u8_t arr1[], u8_t arr2[], u8_t size) {
    for (int i = 0; i < size; ++i) {
        if (arr1[i] != arr2[i]) {
            return false;
        }
    }
    return true;
}

static void parse_data(uint8_t byData, bool_t is_data_new) {
    static uint16_t expected_length = 0;
    static uint16_t current_index = 0;
    static uint16_t crc = 0;
    
    if(is_data_new) {
        m_enRecvState = FRS_LENGTH;
        expected_length = 0;
        current_index = 0;
        crc = 0;
    }

    switch(m_enRecvState) {
        case FRS_LENGTH:
            expected_length = byData;
            current_index = 0;
            // Kiểm tra length hợp lệ (tối thiểu phải có: length + address + command + status + CRC)
            if (expected_length >= 5 && expected_length <= MAX_PACKET_SIZE) {
                m_enRecvState = FRS_ADDRESS;
                // Length - 3 vì không tính address và 2 byte CRC
                ex10_packet = Packet(expected_length - 3);
            } else {
                m_enRecvState = FRS_LENGTH;
                ESP_LOGW(TAG, "Invalid length: %d", expected_length);
            }
            break;
            
        case FRS_ADDRESS:
        {
            if(byData == READER_ADDRESS){
                m_enRecvState = FRS_COMMAND;
                current_index ++;
            }
            else{
                m_enRecvState = FRS_LENGTH;
                ESP_LOGW(TAG, "Invalid address: 0x%02X", byData);
            }

            break;
        }
        case FRS_COMMAND:
            current_index ++;
            m_enRecvState = FRS_STATUS;
            ex10_packet.Push(byData);
            break;
        case FRS_STATUS:
            // current_index ++;
            ex10_packet.Push(byData);
            if(current_index++ == expected_length - 3) {
                m_enRecvState = FRS_CHECKSUM_LOW;
                break;
            }
            m_enRecvState = FRS_PAYLOAD;
            break;

        case FRS_PAYLOAD:
            // current_index++;
            ex10_packet.Push(byData);
            if(current_index++ >= expected_length - 3) {
                m_enRecvState = FRS_CHECKSUM_LOW;
            }
            break;
        case FRS_CHECKSUM_LOW:
            current_index ++;
            crc = byData & 0xFF;
            m_enRecvState = FRS_CHECKSUM_HIGH;
            break;  
        case FRS_CHECKSUM_HIGH: {
            current_index++;
            crc |= (byData << 8);
            
            // Tính CRC trên toàn bộ dữ liệu (trừ 2 byte CRC)
            uint8_t buff[ex10_packet.Length() + 2];
            buff[0] = expected_length;
            buff[1] = READER_ADDRESS;
            memcpy(buff + 2, ex10_packet.GetBuffer(), ex10_packet.Length());
            
            if(uiCrc16Cal(buff, ex10_packet.Length() + 2) == crc) {
                tag_manager_process(ex10_packet.GetBuffer(), ex10_packet.Length());
            } else {
                ESP_LOGW(TAG, "CRC check failed");
            }
            m_enRecvState = FRS_LENGTH;
            break;
        }
    
        case FRS_RX_TIMEOUT:
            m_enRecvState = FRS_LENGTH;
            break;
	    default:
	        m_enRecvState = FRS_LENGTH;
                break;
	    }
}
