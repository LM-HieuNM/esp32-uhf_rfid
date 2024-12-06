#include "typedefs.h"
#include <vector>
#include <bits/stdc++.h>
#include <algorithm>
#include "typedefs.h"
#include <iterator>
#include <string>

#define TID_LEN 12

struct tag_info_t {
    std::vector<u8_t> tagEPC;     // Dùng vector vì EPC có độ dài thay đổi
    std::array<u8_t, TID_LEN> tagTID;
    u8_t antenna;
    u32_t rssi;
    u32_t phase;
    u32_t freq;
    u32_t count;
};

class TagList {
private:
    std::vector<tag_info_t> tags;  // Danh sách các thẻ

public:
    TagList();
    ~TagList();

    void AddOrUpdateTag(const std::vector<u8_t>& tagEPC, 
                       const std::array<u8_t, TID_LEN>& tagTID,
                       u8_t antenna, u32_t rssi, u32_t phase, u32_t freq);

    size_t GetUniqueTagCount() const {
        return tags.size();
    }

    u16_t GetTotalReadCount() const;

    // Xóa toàn bộ danh sách
    void Clear() {
        tags.clear();
    }

    const tag_info_t* GetTagByEPC(const std::vector<u8_t>& tagEPC) const;
    std::string GetJsonString() const;
    // Iterator để duyệt danh sách thẻ
    auto begin() { return tags.begin(); }
    auto end() { return tags.end(); }
};