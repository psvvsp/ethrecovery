/*
    pbkdf2 and HMAC implementation
    requires implementation of PRF (pseudo-random function),
      probably using HMAC and an implementation of hash_main
*/
/*
    REQ: outBuf.buffer must have space for ceil(dkLen / PRF_output_bytes) * PRF_output_bytes
    REQ: PRF implementation MUST allow that output may be the salt (m in hmac)
    inBuffer / pwdBuffer / the like are not const to allow for padding
*/

#include "pbkdf2.h"
#include "sha512.h"


// Determine (statically) the actual required buffer size
// Correct for both 64 & 32 bit
//   Just allowing for MD padding: 2 words for length, 1 for the 1-pad = 3 words
#define sizeForHash(reqSize) (ceilDiv((reqSize) + 2 + 1, hashBlockSize) * hashBlockSize)

#if wordSize == 4
__constant__ const unsigned int opad = 0x5c5c5c5c;
__constant__ const unsigned int ipad = 0x36363636;
#elif wordSize == 8
__constant__ const word opad = 0x5c5c5c5c5c5c5c5c;
__constant__ const word ipad = 0x3636363636363636;
#endif

__constant__ const word xoredPad = opad ^ ipad;

// Slightly ugly: large enough for hmac_main usage, and tight for pbkdf2
#define m_buffer_size (saltBufferSize + 1)

__device__ void hmac(const word* K, const word K_len_bytes,
    const word* m, const word m_len_bytes, word* output)
{
    // REQ: If K_len_bytes isn't divisible by 4/8, final word should be clean (0s to the end)
    // REQ: s digestSize is a multiple of 4/8 bytes

    /* Declare the space for input to the last hash function:
         Compute and write K_ ^ opad to the first block of this. This will be the only place that we store K_ */

#define size_2 sizeForHash(hashBlockSize + hashDigestSize)
    word input_2[size_2] = { 0 };
#undef size_2

    word end;
    if (K_len_bytes <= hashBlockSize_bytes)
    {
        end = ceilDiv(K_len_bytes, wordSize);
        // XOR with opad and slightly pad with zeros..
        for (int j = 0; j < end; j++) {
            input_2[j] = K[j] ^ opad;
        }
    }
    else {
        end = hashDigestSize;
        // Hash K to get K'. XOR with opad..
        hash_glbl_to_priv(K, K_len_bytes, input_2);
        for (int j = 0; j < hashDigestSize; j++) {
            input_2[j] ^= opad;
        }
    }
    // And if short, pad with 0s to the BLOCKsize, completing xor with opad
    for (int j = end; j < hashBlockSize; j++) {
        input_2[j] = opad;
    }

    // Copy K' ^ ipad into the first block.
    // Be careful: hash needs a whole block after the end. ceilDiv from buffer_structs
#define size_1 sizeForHash(hashBlockSize + m_buffer_size)

// K' ^ ipad into the first block
    word input_1[size_1] = { 0 };
    word temp_output[size_1] = { 0 };
#undef size_1
    for (int j = 0; j < hashBlockSize; j++) {
        input_1[j] = input_2[j] ^ xoredPad;
    }

    // Slightly inefficient copying m in..
    word m_len_word = ceilDiv(m_len_bytes, wordSize);
    for (int j = 0; j < m_len_word; j++) {
        input_1[hashBlockSize + j] = m[j];
    }

    // Hash input1 into the second half of input2
    word leng = hashBlockSize_bytes + m_len_bytes;
    hash_private(input_1, leng, input_2 + hashBlockSize);

    // Hash input2 into output!
    hash_private(input_2, hashBlockSize_bytes + hashDigestSize_bytes, temp_output);
    for (int j = 0; j < hashBlockSize; j++) {
        output[j] = temp_output[j];
    }
}

#undef sizeForHash


// PRF
#define PRF_output_size hashDigestSize
#define PRF_output_bytes (PRF_output_size * wordSize)
// Our PRF is the hmac using the hash. Commas remove need for bracketing
#define PRF(pwd, pwdLen_bytes, salt, saltLen_bytes, output) \
    hmac(pwd, pwdLen_bytes, salt, saltLen_bytes, output)


__device__ static void F(const word* pwd, const word pwdLen_bytes,
    word* salt, const word saltLen_bytes,
    const unsigned int iters, unsigned int callI,
    word* output)
{
    // ASSUMPTION: salt array has wordSize bytes more room
    // Note salt is not const, so we can efficiently tweak the end of it

    // Add the integer to the end of the salt
    // NOTE! Always adding callI as just a u32
    word overhang = saltLen_bytes % wordSize;
    overhang *= 8; // convert to bits
    word saltLastI = saltLen_bytes / wordSize;

    // ! Crucial line: BE, moved as if it's a u32 but still within the word
    word be_callI = SWAP((word)callI) >> (8 * (wordSize - 4));
    if (overhang > 0)
    {
        salt[saltLastI] |= be_callI << overhang;
        salt[saltLastI + 1] = be_callI >> ((8 * wordSize) - overhang);
    }
    else
    {
        salt[saltLastI] = be_callI;
    }

    // Make initial call, copy into output
    // This copy is avoidable, but only with __global / __private macro stuff
    word u[PRF_output_size] = { 0 };
    // +4 is correct even for 64 bit
    PRF(pwd, pwdLen_bytes, salt, saltLen_bytes + 4, u);
    for (unsigned int j = 0; j < PRF_output_size; j++) {
        output[j] = u[j];
    }

#define xor(x,acc)                                  \
    /* xors PRF output x onto acc*/                     \
    {                                                   \
        for (int k = 0; k < PRF_output_size; k++){     \
            acc[k] ^= x[k];                             \
        }                                               \
    }

    // Perform all the iterations, reading salt from- AND writing to- u.
    for (unsigned int j = 1; j < iters; j++) {
        PRF(pwd, pwdLen_bytes, u, PRF_output_bytes, u);
        xor (u, output);
    }
}

__device__ void pbkdf2(
    const word *inbuffer, word inbufferSizeBytes,
    const word *saltbuffer, word saltbufferSizeBytes,
    word *outbuffer,
    unsigned int iters, unsigned int dkLen_bytes)
{
    word saltbufferSize = ceilDiv(saltbufferSizeBytes, wordSize);
    word personal_salt[saltBufferSize + 2] = { 0 };
    for (int j = 0; j < saltbufferSize; j++) {
        personal_salt[j] = saltbuffer[j];
    }

    // Determine the number of calls to F that we need to make
    unsigned int nBlocks = ceilDiv(dkLen_bytes, PRF_output_bytes);
    for (unsigned int j = 1; j <= nBlocks; j++)
    {
        F(inbuffer, inbufferSizeBytes, personal_salt, saltbufferSizeBytes, iters, j, outbuffer);
        outbuffer += PRF_output_size;
    }
}
