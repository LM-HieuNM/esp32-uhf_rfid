#ifndef SNTP_TIME_H__
#define SNTP_TIME_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t get_timestamp(void);
char* get_iso_timestamp(void);
void init_time_sntp(void);

#ifdef __cplusplus
}
#endif

#endif