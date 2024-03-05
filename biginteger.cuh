#pragma once

#include <cstdint>

template <size_t WORDS>
class BigInteger
{
public:
	__device__ BigInteger(uint32_t* buffer);

	__device__ void operator += (const BigInteger<WORDS>& bi);
	__device__ void operator -= (const BigInteger<WORDS>& bi);

	__device__ bool operator < (const BigInteger<WORDS>& bi);
	__device__ void mod(const BigInteger<WORDS>& bi);

	__device__ const uint32_t* get() const { return m_buffer; }

private:
	uint32_t m_first;
	uint32_t *m_buffer;
};

template<size_t WORDS>
__device__  BigInteger<WORDS>::BigInteger(uint32_t* buffer)
{
	m_first = 0;
	m_buffer = buffer;
}

template<size_t WORDS>
__device__  void BigInteger<WORDS>::operator+=(const BigInteger<WORDS>& bi)
{
	uint64_t sum = 0;
	for (uint32_t i = WORDS - 1; i != uint32_t(-1); i--) {
		sum += uint64_t(m_buffer[i]) + uint64_t(bi.m_buffer[i]);
		m_buffer[i] = uint32_t(sum & 0xFFFFFFFF);
		sum >>= 32;
	}
	m_first = uint32_t(sum) + bi.m_first;
}

template<size_t WORDS>
__device__  void BigInteger<WORDS>::operator-=(const BigInteger<WORDS>& bi)
{
	uint32_t carry = 0u;
	for (uint32_t i = WORDS - 1; i != uint32_t(-1); i--) {
		if (m_buffer[i] < carry) {
			carry = 1;
			m_buffer[i] = 0xFFFFFFFF - bi.m_buffer[i];
		}
		else {
			m_buffer[i] -= carry;
			if (m_buffer[i] >= bi.m_buffer[i]) {
				carry = 0u;
				m_buffer[i] -= bi.m_buffer[i];
			}
			else {
				carry = 1u;
				m_buffer[i] = uint32_t(0x100000000ull + uint64_t(m_buffer[i]) - uint64_t(bi.m_buffer[i]));
			}
		}
	}
	m_first -= (carry + bi.m_first);
	assert(m_first == 0 || m_first == 1);
}

template<size_t WORDS>
__device__ bool BigInteger<WORDS>::operator<(const BigInteger<WORDS>& bi)
{
	if (m_first < bi.m_first)
		return true;
	if (m_first > bi.m_first)
		return false;

	for (uint32_t i = 0; i < WORDS; i++) {
		if (m_buffer[i] < bi.m_buffer[i]) 
			return true;
		if (m_buffer[i] > bi.m_buffer[i])
			return false;
	}
	return false;
}

template<size_t WORDS>
__device__ void BigInteger<WORDS>::mod(const BigInteger<WORDS>& bi)
{
	while (!(*this < bi))
		*this -= bi;
}


