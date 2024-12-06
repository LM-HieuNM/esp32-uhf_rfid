/*
 * Packet.cpp
 *
 *  Created on: Apr 19, 2024
 *      Author: HieuNM
 */

#include "packet.hpp"
#include <bits/stdc++.h>
#include <algorithm>

Packet::Packet(
    u32_t dwLength
) : m_pbyBuffer (nullptr)
  , m_dwLength (dwLength)
  , m_dwCount (0) {
    if (dwLength > 0) {
        m_pbyBuffer = new u8_t[dwLength];
    }
}

Packet::Packet(
    const Packet& copied
) : m_pbyBuffer (nullptr)
  , m_dwLength (copied.m_dwLength)
  , m_dwCount (copied.m_dwCount) {
    m_pbyBuffer = new u8_t[m_dwLength];
    std::copy(copied.m_pbyBuffer, copied.m_pbyBuffer + m_dwLength, m_pbyBuffer);
}

Packet::~Packet(
) {
    if (m_pbyBuffer != nullptr) {
        delete[] m_pbyBuffer;
        m_pbyBuffer = nullptr;
    }
}

void
Packet::Reset(
) {
    if (m_pbyBuffer != nullptr) {
        delete[] m_pbyBuffer;
        m_pbyBuffer = nullptr;
    }
    m_dwLength = 0;
    m_dwCount = 0;
}

void
Packet::Swap(
    Packet& other
) {
    std::swap(m_dwCount, other.m_dwCount);
    std::swap(m_dwLength, other.m_dwLength);
    std::swap(m_pbyBuffer, other.m_pbyBuffer);
}

bool_t
Packet::Push(
    u8_t byData
) {
    if (m_dwCount + 1 > m_dwLength) {
        m_dwLength = m_dwCount + 1;
        auto temp = new u8_t[m_dwLength];
        for (u32_t i = 0; i < m_dwCount; i++) {
            temp[i] = m_pbyBuffer[i];
        }
        if (m_pbyBuffer != nullptr) {
            delete[] m_pbyBuffer;
            m_pbyBuffer = nullptr;
        }
        m_pbyBuffer = temp;
    }
    m_pbyBuffer[m_dwCount++] = byData;
    return TRUE;
}

bool_t
Packet::Push(
    u8_p  pbBuffer,
    u32_t dwLength
) {
    if (m_dwCount + dwLength > m_dwLength) {
        m_dwLength = m_dwCount + dwLength;
        auto temp = new u8_t[m_dwLength];
        for (u32_t i = 0; i < m_dwCount; i++) {
            temp[i] = m_pbyBuffer[i];
        }
        if (m_pbyBuffer != nullptr) {
            delete[] m_pbyBuffer;
            m_pbyBuffer = nullptr;
        }
        m_pbyBuffer = temp;
    }

    for (u32_t i = 0; i < dwLength; i++) {
        m_pbyBuffer[m_dwCount++] = pbBuffer[i];
    }
    return TRUE;
}

u8_p
Packet::GetBuffer(
) const {
    return m_pbyBuffer;
}

u8_t
Packet::AtPosition(
    u32_t dwPosition
) const {
    if (dwPosition >= m_dwLength) {
        // THROW_EXCEPTION_INVALIDARG();
    }
    return m_pbyBuffer[dwPosition];
}

u8_t
Packet::operator[] (
    u32_t dwPosition
) const {
    return m_pbyBuffer[dwPosition];
}

u32_t
Packet::Count(
) const {
    return m_dwCount;
}

u32_t
Packet::Length(
) const {
    return m_dwLength;
}

bool_t
Packet::IsEmpty(
) const {
    return (bool_t) (m_dwCount == 0);
}

bool_t
Packet::IsFull(
) const {
    return (bool_t) (m_dwCount >= m_dwLength);
}

void
Packet::ResetPacket(
    u32_t dwLength
) {
    if (dwLength > 0) {
        if (m_pbyBuffer != nullptr) {
            delete[] m_pbyBuffer;
            m_pbyBuffer = nullptr;
        }
        m_pbyBuffer = new u8_t[dwLength];
        m_dwLength = dwLength;
        m_dwCount  = 0;
    }
}

void
Packet::Edit(
    u8_t byData,
    u32_t dwPosition
) {
    if (dwPosition >= m_dwLength) {
        // THROW_EXCEPTION_INVALIDARG();
    }
    m_pbyBuffer[dwPosition] = byData;
}

Packet&
Packet::operator= (
    const Packet& copied
) {
    Packet tmp(copied);
    Swap(tmp);
    return *this;
}


