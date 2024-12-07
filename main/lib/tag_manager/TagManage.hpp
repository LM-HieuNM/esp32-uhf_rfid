/*
 * TagManager.hpp
 *
 *  Created on: Apr 19, 2024
 *      Author: HieuNM
 */

#ifndef USER_TAGMANAGER_HPP_
#define USER_TAGMANAGER_HPP_

#ifdef __cplusplus
extern "C" {
#endif

#include "typedefs.h"
#include "app_nvs.h"

void tag_manager_init(uint8_t protocol_type);
void tag_manager_process(u8_p payload, u8_t len);
char* create_json_command(void);
void init_time_sntp(void);
unsigned int uiCrc16Cal(unsigned char const  * pucY, unsigned char ucX);
#ifdef __cplusplus
}
#endif

#endif /* USER_TAGMANAGER_HPP_ */
