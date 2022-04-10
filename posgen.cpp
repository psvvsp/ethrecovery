#include "posgen.h"

static inline unsigned pack(unsigned pos0, unsigned pos1 = 0, unsigned pos2 = 0, unsigned pos3 = 0)
{
	return pos0 | (pos1 << 8) | (pos2 << 16) | (pos3 << 24);
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

	unsigned size = numerator / denominator;
	std::vector<unsigned> result(size, unsigned(-1));

	if (m_missingWords == 1) {

		for (unsigned i = 0; i <= guessLength; i++)
			result.at(i) = pack(i);
	}
	else if (m_missingWords == 2) {

		unsigned cnt = 0;
		for (unsigned i = 0; i <= guessLength; i++)
			for (unsigned j = i; j <= guessLength; j++)
				result.at(cnt++) = pack(i, j);

		assert(cnt == size);
	}
	else if (m_missingWords == 3) {

		unsigned cnt = 0;
		for (unsigned i = 0; i <= guessLength; i++)
			for (unsigned j = i; j <= guessLength; j++)
				for (unsigned k = j; k <= guessLength; k++)
					result.at(cnt++) = pack(i, j, k);

		assert(cnt == size);
	}
	else if (m_missingWords == 4) {

		unsigned cnt = 0;
		for (unsigned i = 0; i <= guessLength; i++)
			for (unsigned j = i; j <= guessLength; j++)
				for (unsigned k = j; k <= guessLength; k++)
					for (unsigned l = k; l <= guessLength; l++)
						result.at(cnt++) = pack(i, j, k, l);

		assert(cnt == size);
	}
	else
		assert(false);

	return result;
}
