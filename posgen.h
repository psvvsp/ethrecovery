#pragma once

#include <cassert>
#include <vector>

class PosGen
{
public:
	PosGen(unsigned mnemonicLength, unsigned missingWords)
		: m_mnemonicLength(mnemonicLength)
		, m_missingWords(missingWords)
	{
		assert(12 <= m_mnemonicLength && m_mnemonicLength <= 24);
		assert(1 <= m_missingWords && m_missingWords <= 4);
	}

	std::vector<unsigned> gen() const;
		
private:
	unsigned m_mnemonicLength;
	unsigned m_missingWords;
};