#pragma once

#include "common.h"

__device__ void hash_glbl_to_priv(const word* input, const unsigned int length, word* hash);
__device__ void hash_private(const word* input, const unsigned int length, word* hash);
