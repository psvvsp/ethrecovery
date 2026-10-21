#pragma once

#include <cassert>
#include <set>
#include <vector>

class PosGen
{
public:
	PosGen(unsigned mnemonicLength, unsigned missingWords, const std::set<std::size_t> &missingPositions)
		: m_mnemonicLength(mnemonicLength)
		, m_missingWords(missingWords)
		, m_missingPositions(missingPositions)
	{
		assert(12 <= m_mnemonicLength && m_mnemonicLength <= 24);
		assert(1 <= m_missingWords && m_missingWords <= 4);
	}

	std::vector<unsigned> gen() const;
		
private:
	bool valid(unsigned pos0) const;
	bool valid(unsigned pos0, unsigned pos1) const;
	bool valid(unsigned pos0, unsigned pos1, unsigned pos2) const;
	bool valid(unsigned pos0, unsigned pos1, unsigned pos2, unsigned pos3) const;

	unsigned m_mnemonicLength;
	unsigned m_missingWords;
	std::set<std::size_t> m_missingPositions;
};