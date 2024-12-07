#ifndef ESP_HID_DEVICE_MAIN_H
#define ESP_HID_DEVICE_MAIN_H
#ifdef __cplusplus
extern "C" {
#endif
void ble_hid_init(const char* device_name, uint32_t pin_code);
void esp_hidd_send_consumer_value(const char* json_string);
#ifdef __cplusplus
}
#endif
#endif