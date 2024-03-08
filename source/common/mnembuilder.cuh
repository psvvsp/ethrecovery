#pragma once

#include <cstdint>
#include <memory>

template<uint32_t MNEMONIC_LENGTH, uint32_t MAX_WORD_SIZE>
class MnemBuilder
{
public:
	__device__
	MnemBuilder(const uint8_t* dict, uint32_t dictSize)
		: m_dict(dict), m_dictSize(dictSize)
	{
		m_size = 0; m_word = 0;
		memset(m_mnemo, 0, sizeof(m_mnemo));
	}

	__device__
	void add(uint16_t wordId)
	{
		uint8_t* mnemo = reinterpret_cast<uint8_t*>(m_mnemo);

		assert(m_word < MNEMONIC_LENGTH);
		m_word++;

		assert(wordId < m_dictSize);
		const uint8_t* word = m_dict + (MAX_WORD_SIZE + 1) * wordId;

		if (m_size > 0)
			mnemo[m_size++] = ' ';

		uint32_t i;
		for (i = 0; i < MAX_WORD_SIZE; i++) {
			if (word[i]) mnemo[m_size++] = word[i];
			else break;
		}

		assert(i > 0 && word[i] == 0);
	}

	__device__
	const uint64_t* mnemo() const { return m_mnemo; }

	__device__
	uint32_t mnemoSizeBytes() const { return m_size; }


private:
	enum{MAX_MNEMO_SIZE_BYTES = MNEMONIC_LENGTH*MAX_WORD_SIZE + (MNEMONIC_LENGTH - 1)};
	enum{MAX_MNEMO_SIZE = (MAX_MNEMO_SIZE_BYTES + 7) / 8 };

	const uint8_t* m_dict;
	const uint32_t m_dictSize;

	uint32_t m_size;
	uint32_t m_word;
	uint64_t m_mnemo[MAX_MNEMO_SIZE + 3];
};