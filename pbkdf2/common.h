#pragma once

// All macros left defined for usage in the program
#define ceilDiv(n,d) (((n) + (d) - 1) / (d))

#define wordSize 8

// Practical sizes of buffers, in words.
#define inBufferSize ceilDiv(256, wordSize)
#define outBufferSize ceilDiv(64, wordSize)
#define pwdBufferSize ceilDiv(32, wordSize)
#define saltBufferSize ceilDiv(16, wordSize)
#define ctBufferSize ceilDiv(0, wordSize)

// 
#define hashBlockSize_bytes ceilDiv(1024, 8) /* Needs to be a multiple of 4, or 8 when we work with unsigned longs */
#define hashDigestSize_bytes ceilDiv(512, 8)

// just Size always implies _word
#define hashBlockSize ceilDiv(hashBlockSize_bytes, wordSize)
#define hashDigestSize ceilDiv(hashDigestSize_bytes, wordSize)


#if wordSize == 8
    // Initially for use in SHA-512
#define hashBlockSize_long64 hashBlockSize
#define hashDigestSize_long64 hashDigestSize
#define word unsigned long long
#define rotl64(a,n) (((a) << (n)) | ((a) >> (64 - (n))))
#define rotr64(a,n) (((a) >> (n)) | ((a) << (64 - (n))))

__device__ inline word SWAP(const word val)
{
    // ab cd ef gh -> gh ef cd ab using the 32 bit trick
    word tmp = (rotr64(val & 0x0000FFFF0000FFFFUL, 16UL) | rotl64(val & 0xFFFF0000FFFF0000UL, 16UL));

    // Then see this as g- e- c- a- and -h -f -d -b to swap within the pairs,
    // gh ef cd ab -> hg fe dc ba
    return (rotr64(tmp & 0xFF00FF00FF00FF00UL, 8UL) | rotl64(tmp & 0x00FF00FF00FF00FFUL, 8UL));
}
#endif

#define __global
#define __private