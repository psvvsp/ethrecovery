#pragma once

#include <cuda_runtime.h>
#include <iostream>

#define CUDA_CALL(ans) { gpuAssert((ans), __FILE__, __LINE__); }
#define CUDA_CHECK(location) { gpuAssert(cudaDeviceSynchronize(), __FILE__, __LINE__); }

inline void gpuAssert(cudaError_t code, const char* file, int line) {
    if (code != cudaSuccess) {
        std::cerr << "CUDA ERROR: " << file << "(" << line << "): " << cudaGetErrorString(code);
        exit(EXIT_FAILURE);
    }
}
