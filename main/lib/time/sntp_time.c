#include "esp_sntp.h"
#include <time.h>
#include <sys/time.h>
#include "sntp_time.h"

#define TASK_TAG "TIME"
time_t now;

void time_sync_notification_cb(struct timeval *tv)
{
}
static void initialize_sntp(void)
{
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
    sntp_set_time_sync_notification_cb(time_sync_notification_cb);
#ifdef CONFIG_SNTP_TIME_SYNC_METHOD_SMOOTH
    sntp_set_sync_mode(SNTP_SYNC_MODE_SMOOTH);
#endif
    sntp_init();
}


static void obtain_time(void)
{

    initialize_sntp();

    // wait for time to be set
    time_t now = 0;
    struct tm timeinfo = { 0 };
    int retry = 0;
    const int retry_count = 10;
    while (sntp_get_sync_status() == SNTP_SYNC_STATUS_RESET && ++retry < retry_count) {
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
    time(&now);
    localtime_r(&now, &timeinfo);

}

void init_time_sntp(void){

	struct tm timeinfo;
	time(&now);
	localtime_r(&now, &timeinfo);
	// Is time set? If not, tm_year will be (1970 - 1900).
	if (timeinfo.tm_year < (2016 - 1900)) {
		obtain_time();
		// update 'now' variable with current time
		time(&now);
	}
   time_t timestamp = now;
}

uint32_t get_timestamp(void) {
    time(&now);
    return now;
}


char* get_iso_timestamp(void) {
    static char iso_time[40];
    
    time_t now = get_timestamp();
    struct tm timeinfo;
    localtime_r(&now, &timeinfo);
    
    strftime(iso_time, sizeof(iso_time), "%Y-%m-%dT%H:%M:%S", &timeinfo);

    strcat(iso_time, "+07:00");
    
    return iso_time;
}