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

typedef struct {
    int power;
    bool antennas[16];
} antenna_config_t;
extern antenna_config_t current_antenna_config;

void tag_manager_init(void);
void tag_manager_process(u8_p payload, u8_t len);
char* create_json_command(void);
void init_time_sntp(void);
unsigned int uiCrc16Cal(unsigned char const  * pucY, unsigned char ucX);
#ifdef __cplusplus
}
#endif

#endif /* USER_TAGMANAGER_HPP_ */
