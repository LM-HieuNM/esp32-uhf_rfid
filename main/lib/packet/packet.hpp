/*
 * Packet.hpp
 *
 *  Created on: Apr 19, 2024
 *      Author: HieuNM
 */

#ifndef MAIN_PACKET_HPP_
#define MAIN_PACKET_HPP_

#ifdef __cplusplus
extern "C" {
#endif


#include "typedefs.h"


class Packet {
private:
    u8_p    m_pbyBuffer;
    u32_t   m_dwLength;
    u32_t   m_dwCount;

protected:
    void Swap(Packet& other);

public:
    Packet(u32_t dwLength = 0);

    Packet(const Packet& copied);

    virtual ~Packet();

    Packet& operator= (const Packet& copied);

    virtual void Reset();

    virtual void ResetPacket(u32_t dwLength);

    virtual void Edit(u8_t byData, u32_t dwPosition);

    virtual bool_t Push(u8_t byData);

    virtual bool_t Push(u8_p pbyBuffer, u32_t dwLength);

    virtual u8_p GetBuffer() const;

    virtual u8_t AtPosition(u32_t dwPosition) const;

    virtual u8_t operator[](u32_t dwPosition) const;

    virtual u32_t Count() const;

    virtual u32_t Length() const;

    virtual bool_t IsEmpty() const;

    virtual bool_t IsFull() const;
};

typedef Packet  Packet_t;
typedef Packet* Packet_p;

#ifdef __cplusplus
}
#endif
#endif /* MAIN_PACKET_HPP_ */
