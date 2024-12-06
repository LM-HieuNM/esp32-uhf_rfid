/*
 * serial.hpp
 *
 *  Created on: Apr 19, 2024
 *      Author: HieuNM
 */

#ifndef USER_SERIAL_HPP_
#define USER_SERIAL_HPP_

#ifdef __cplusplus
extern "C" {
#endif

#include "stdint.h"

typedef enum {
    FRS_LENGTH,
    FRS_ADDRESS,
    FRS_COMMAND,
    FRS_STATUS,   
    FRS_PAYLOAD,
    FRS_CHECKSUM_LOW,
    FRS_CHECKSUM_HIGH,
    FRS_RX_TIMEOUT
} RecvState_t;

void serial_init(void);

int send_buffer(const uint8_t* data, uint16_t length);

#ifdef __cplusplus
}
#endif
#endif /* USER_SERIAL_HPP_ */
