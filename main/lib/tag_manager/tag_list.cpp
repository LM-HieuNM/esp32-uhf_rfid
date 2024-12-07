#include "sntp_time.h"
#include "cJSON.h"
#include "tag_list.hpp"

TagList::TagList() {}
TagList::~TagList() {}
void TagList::AddOrUpdateTag(const std::vector<u8_t>& tagEPC, 
                       const std::array<u8_t, TID_LEN>& tagTID,
                       u8_t antenna, u32_t rssi, u32_t phase, u32_t freq) {
    // Tìm thẻ trong danh sách
    for(auto& tag : tags) {
        if(tag.tagEPC == tagEPC) {
            // Cập nhật thông tin nếu thẻ đã tồn tại
            tag.tagTID = tagTID;
            tag.antenna = antenna;
            tag.rssi = rssi;
            tag.phase = phase;
            tag.freq = freq;
            tag.count++;
            return;
        }
    }

    // Thêm thẻ mới nếu chưa tồn tại
    tag_info_t newTag = {
        .tagEPC = tagEPC,
        .tagTID = tagTID,
        .antenna = antenna,
        .rssi = rssi,
        .phase = phase,
        .freq = freq,
        .count = 1
    };
    tags.push_back(newTag);
}
u16_t TagList::GetTotalReadCount() const {
    u16_t total = 0;
    for(const auto& tag : tags) {
        total += tag.count;
    }
    return total;
}

const tag_info_t* TagList::GetTagByEPC(const std::vector<u8_t>& tagEPC) const {
    for(const auto& tag : tags) {
        if(tag.tagEPC == tagEPC) {
            return &tag;
        }
    }
    return nullptr;
}

std::string TagList::GetJsonString() const {
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return "";

    cJSON_AddStringToObject(root, "type", "INVENTORY");
    cJSON_AddStringToObject(root, "timestamp", get_iso_timestamp());
    cJSON_AddNumberToObject(root, "total", GetTotalReadCount());

    // Tạo object data
    cJSON *data = cJSON_CreateObject();
    if (data == NULL) {
        cJSON_Delete(root);
        return "";
    }
    cJSON_AddItemToObject(root, "data", data);

    // Duyệt qua từng tag trong danh sách
    for (const auto& tag : tags) {
        // Chuyển EPC thành string hex để làm key
        std::stringstream ss;
        for (const auto& byte : tag.tagEPC) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::string epcStr = ss.str();

        // Tạo object cho mỗi tag
        cJSON *tagObj = cJSON_CreateObject();
        if (tagObj == NULL) continue;

        // Chuyển TID thành string hex
        ss.str("");
        ss.clear();
        for (const auto& byte : tag.tagTID) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::string tidStr = ss.str();

        // Thêm thông tin của tag
        cJSON_AddStringToObject(tagObj, "TID", tidStr.c_str());
        cJSON_AddNumberToObject(tagObj, "antenna", tag.antenna);
        cJSON_AddNumberToObject(tagObj, "channel", tag.freq);
        cJSON_AddNumberToObject(tagObj, "eventNum", tag.count);
        cJSON_AddStringToObject(tagObj, "format", "epc");
        cJSON_AddStringToObject(tagObj, "idHex", epcStr.c_str());
        cJSON_AddNumberToObject(tagObj, "peakRssi", tag.rssi);
        cJSON_AddNumberToObject(tagObj, "phase", tag.phase);
        cJSON_AddNumberToObject(tagObj, "reads", 1);

        // Thêm object tag vào data với key là EPC
        cJSON_AddItemToObject(data, epcStr.c_str(), tagObj);
    }

    // Chuyển đổi sang chuỗi
    char *jsonString = cJSON_Print(root);
    std::string result;
    if (jsonString) {
        result = std::string(jsonString);
        free(jsonString);
    }

    // Giải phóng bộ nhớ
    cJSON_Delete(root);

    return result;
}

std::string TagList::GetSingleTagJsonString(size_t index) const {
    if (index >= tags.size()) return "";

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return "";

    cJSON_AddStringToObject(root, "type", "INVENTORY");
    cJSON_AddStringToObject(root, "timestamp", get_iso_timestamp());
    cJSON_AddNumberToObject(root, "total", 1);

    // Tạo object data
    cJSON *data = cJSON_CreateObject();
    if (data == NULL) {
        cJSON_Delete(root);
        return "";
    }
    cJSON_AddItemToObject(root, "data", data);

    // Lấy tag tại index
    const auto& tag = tags[index];
    
    // Chuyển EPC thành string hex để làm key
    std::stringstream ss;
    for (const auto& byte : tag.tagEPC) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::string epcStr = ss.str();

    // Tạo object cho tag
    cJSON *tagObj = cJSON_CreateObject();
    if (tagObj == NULL) {
        cJSON_Delete(root);
        return "";
    }

    // Chuyển TID thành string hex
    ss.str("");
    ss.clear();
    for (const auto& byte : tag.tagTID) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::string tidStr = ss.str();

    // Thêm thông tin của tag
    cJSON_AddStringToObject(tagObj, "TID", tidStr.c_str());
    cJSON_AddNumberToObject(tagObj, "antenna", tag.antenna);
    cJSON_AddNumberToObject(tagObj, "channel", tag.freq);
    cJSON_AddNumberToObject(tagObj, "eventNum", tag.count);
    cJSON_AddStringToObject(tagObj, "format", "epc");
    cJSON_AddStringToObject(tagObj, "idHex", epcStr.c_str());
    cJSON_AddNumberToObject(tagObj, "peakRssi", tag.rssi);
    cJSON_AddNumberToObject(tagObj, "phase", tag.phase);
    cJSON_AddNumberToObject(tagObj, "reads", 1);

    // Thêm object tag vào data với key là EPC
    cJSON_AddItemToObject(data, epcStr.c_str(), tagObj);

    // Chuyển đổi sang chuỗi
    char *jsonString = cJSON_Print(root);
    std::string result;
    if (jsonString) {
        result = std::string(jsonString);
        free(jsonString);
    }

    // Giải phóng bộ nhớ
    cJSON_Delete(root);

    return result;
}

