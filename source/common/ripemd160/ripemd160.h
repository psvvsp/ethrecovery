#pragma once

#include <cstdint>

__device__ void ripemd160(const uint8_t* msg, uint32_t msg_len, uint8_t* hash);
