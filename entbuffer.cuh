#pragma once

#include <cassert>
#include <cuda_runtime.h>

#include <cstdint>
#include <memory>


#define SWAP_4(x) ( ((x) << 24) | \
         (((x) << 8) & 0x00ff0000) | \
         (((x) >> 8) & 0x0000ff00) | \
         ((x) >> 24) )


template<uint32_t Bits, uint32_t Elems>
class EntropyBuffer
{
private:
	static constexpr uint32_t SIZE = 64;
	static constexpr uint32_t size = (Bits * Elems + 7) / 8;
	static_assert(size <= SIZE);

public:
	static constexpr uint32_t checksum_bit_size = Elems / 3;
	static_assert(checksum_bit_size <= 8);

private:
	static constexpr uint32_t entropy_bytes_size = (Bits * Elems - checksum_bit_size) >> 3;
	static_assert(((Bits* Elems - checksum_bit_size) & 7) == 0);

public:

	__device__ __host__
	EntropyBuffer()
	{
		m_counter = 0;
		m_checksum = uint32_t(-1);
		memset(m_buffer, 0, SIZE);
	}

	__device__ __host__
	void append(uint32_t elem)
	{
		assert(m_counter < Elems);
		elem &= ((1 << Bits) - 1);

		uint32_t bits = m_counter * Bits;
		
		uint32_t byte = bits >> 3;
		uint32_t bit = bits & 7u;

		uint32_t head = 8u - bit;
	    uint32_t tail = Bits - head;

		m_buffer[byte] |= (elem >> tail);
		
		uint32_t i;
		for (i = 1; i <= tail >> 3; i++) {
			m_buffer[byte + i] |= ((elem >> (tail - 8u*i)) & 255);
		}
		m_buffer[byte + i] |= ((elem & ((1 << (tail&7)) - 1)) << (8u - (tail&7)));

		m_counter++;

		if (m_counter == Elems) {
			m_checksum = m_buffer[entropy_bytes_size] >> (8 - checksum_bit_size);
			m_buffer[entropy_bytes_size] = 0;

			uint32_t* d = reinterpret_cast<uint32_t*>(m_buffer);
			for (int i = 0; i < 16; i++) {
				uint32_t dd = d[i];
				d[i] = SWAP_4(dd);
			}
		}
	}

	__device__ __host__
	const uint8_t* entropyBytesData() const
	{
		return m_buffer;
	}

	__device__ __host__
	uint32_t entropyBytesSize() const
	{
		return SIZE;
	}

	__device__ __host__
	uint32_t checkSum() const
	{
		return m_checksum;
	}


private:
	uint32_t m_counter;
	uint32_t m_checksum;
	uint8_t m_buffer[SIZE];
};