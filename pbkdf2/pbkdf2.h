#pragma once

#include <cstdint>


__device__ void hmac(const uint64_t* K, const uint64_t K_len_bytes,
    const uint64_t* m, const uint64_t m_len_bytes, uint64_t* output);


__device__ void pbkdf2(
    const uint64_t* inbuffer, uint64_t inbufferSizeBytes,
    const uint64_t* saltbuffer, uint64_t saltbufferSizeBytes,
    uint64_t* outbuffer,
    uint32_t iters, uint32_t dkLen_bytes);
