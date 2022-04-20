#pragma once

#include <cstdint>

__device__ void keccak256(uint32_t* out, const uint32_t* in, uint32_t len);