#include "posgen.h"

#include <algorithm>

static inline unsigned pack(unsigned pos0, unsigned pos1 = 0, unsigned pos2 = 0, unsigned pos3 = 0)
{
	return pos0 | (pos1 << 8) | (pos2 << 16) | (pos3 << 24);
}

bool PosGen::valid(unsigned pos) const
{
	if (m_missingPositions.empty())
		return true;

	return m_missingPositions.count(pos) > 0;
}

bool PosGen::valid(unsigned pos0, unsigned pos1) const
{
	if (m_missingPositions.empty())
		return true;

	bool b0 = (m_missingPositions.count(pos0) > 0);
	bool b1 = (m_missingPositions.count(pos1) > 0);

	if (m_missingPositions.size() == 1) {
		return b0 || b1;
	}

	return b0 && b1;
}

bool PosGen::valid(unsigned pos0, unsigned pos1, unsigned pos2) const
{
	if (m_missingPositions.empty())
		return true;

	bool b0 = (m_missingPositions.count(pos0) > 0);
	bool b1 = (m_missingPositions.count(pos1) > 0);
	bool b2 = (m_missingPositions.count(pos2) > 0);

	if (m_missingPositions.size() == 1) {
		return b0 || b1 || b2;
	}

	if (m_missingPositions.size() == 2) {
		return (b0 && b1) || (b0 && b2) || (b1 && b2);
	}

	return b0 && b1 && b2;
}

bool PosGen::valid(unsigned pos0, unsigned pos1, unsigned pos2, unsigned pos3) const
{
	if (m_missingPositions.empty())
		return true;

	bool b0 = (m_missingPositions.count(pos0) > 0);
	bool b1 = (m_missingPositions.count(pos1) > 0);
	bool b2 = (m_missingPositions.count(pos2) > 0);
	bool b3 = (m_missingPositions.count(pos3) > 0);

	if (m_missingPositions.size() == 1) {
		return b0 || b1 || b2 || b3;
	}

	if (m_missingPositions.size() == 2) {
		return (b0 && b1) || (b0 && b2) || (b0 && b3) || (b1 && b2) || (b1 && b3) || (b2 && b3);
	}

	if (m_missingPositions.size() == 3) {
		return (b0 && b1 && b2) || (b0 && b1 && b3) || (b0 && b2 && b3) || (b1 && b2 && b3);
	}

	return b0 && b1 && b2 && b3;
}

std::vector<unsigned> PosGen::gen() const
{
	unsigned guessLength = m_mnemonicLength - m_missingWords;

	unsigned numerator = 1u;
	unsigned denominator = 1u;

	for (unsigned i = 1; i <= m_missingWords; i++) {
		numerator *= (guessLength + i);
		denominator *= i;
	}

	std::vector<unsigned> result;

	unsigned size = numerator / denominator;
	result.reserve(size);

	if (m_missingWords == 1) {

		for (unsigned i = 0; i < m_mnemonicLength; i++) {
			if (valid(i))
				result.push_back(pack(i));
		}
	}
	else if (m_missingWords == 2) {

		for (unsigned i = 0; i < m_mnemonicLength; i++)
			for (unsigned j = i + 1; j < m_mnemonicLength; j++)
				if (valid(i, j))
					result.push_back(pack(i, j));

		assert(result.size() == size || !m_missingPositions.empty());
	}
	else if (m_missingWords == 3) {

		for (unsigned i = 0; i < m_mnemonicLength; i++)
			for (unsigned j = i + 1; j < m_mnemonicLength; j++)
				for (unsigned k = j + 1; k < m_mnemonicLength; k++)
					if (valid(i, j, k))
						result.push_back(pack(i, j, k));

		assert(result.size() == size || !m_missingPositions.empty());
	}
	else if (m_missingWords == 4) {

		for (unsigned i = 0; i < m_mnemonicLength; i++)
			for (unsigned j = i + 1; j < m_mnemonicLength; j++)
				for (unsigned k = j + 1; k < m_mnemonicLength; k++)
					for (unsigned l = k + 1; l < m_mnemonicLength; l++)
						if (valid(i, j, k, l))
							result.push_back(pack(i, j, k, l));

		assert(result.size() == size || !m_missingPositions.empty());
	}
	else
		assert(false);

	return result;
}
