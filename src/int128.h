#ifndef INT128_H
#define INT128_H

#include <stdint.h>
#include <cstring>

struct UInt128 {
    uint32_t data[4];


    static UInt128 from_update(const uint16_t* update_arr) {
    UInt128 res = {0, 0, 0, 0};
        memcpy(res.data, update_arr, 16);
        return res;
    }

    // Create from a single 32-bit value (useful for Node IDs/Keys)
    static UInt128 from_uint32(uint32_t val) {
        return UInt128{val, 0, 0, 0};
    }

    UInt128 operator^(const UInt128& rhs) const {
        return UInt128{
            data[0] ^ rhs.data[0],
            data[1] ^ rhs.data[1],
            data[2] ^ rhs.data[2],
            data[3] ^ rhs.data[3]
        };
    }

    UInt128& operator^=(const UInt128& rhs) {
        for (int i = 0; i < 4; i++) data[i] ^= rhs.data[i];
        return *this;
    }
    UInt128 operator+(const UInt128& rhs) const {
        UInt128 result = {0};
        uint64_t carry = 0;
        for (int i = 0; i < 4; ++i) {
            uint64_t sum = static_cast<uint64_t>(data[i]) + rhs.data[i] + carry;
            result.data[i] = static_cast<uint32_t>(sum & 0xFFFFFFFF);
            carry = sum >> 32;
        }
        return result;
    }

    UInt128& operator+=(const UInt128& rhs) {
        *this = *this + rhs;
        return *this;
    }

    // TODO: scalar multiplication for verification
    UInt128 operator*(uint32_t scalar) const{
        UInt128 result = {0, 0, 0, 0};
        for(uint32_t i = 0; i < scalar; i++){
            result = result + *this;
        }
        return result;
    }

    UInt128 operator-(const UInt128& rhs) const {
        UInt128 result = {0, 0, 0, 0};
        uint64_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            int64_t diff = static_cast<int64_t>(data[i]) - rhs.data[i] - borrow;
            if (diff < 0) {
                diff += 0x100000000LL;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result.data[i] = static_cast<uint32_t>(diff);
        }
        return result;
    }

    UInt128& operator-=(const UInt128& rhs) {
        *this = *this - rhs;
        return *this;
    }

    bool operator==(const UInt128& rhs) const {
        return data[0] == rhs.data[0] && data[1] == rhs.data[1] && 
               data[2] == rhs.data[2] && data[3] == rhs.data[3];
    }
    
    const uint8_t* as_bytes() const {
        return reinterpret_cast<const uint8_t*>(data);
    }
};

#endif // INT128_H