#include "derivpathstorage.h"

#include <algorithm>
#include <cassert>
#include <fstream>

DerivationPathStorage::DerivationPathStorage()
{
	std::ifstream fin("./derivationpath-lists/ETH.txt");

	std::string line;

	while (getline(fin, line)) {
		
		if (line[0] == '#') 
			continue;
		
		if (std::all_of(line.begin(), line.end(), isspace))
			continue;

		auto it = std::find_if(line.begin(), line.end(), isspace);

		m_paths.push_back(line.substr(0, it - line.begin()));
	}
}

std::vector<uint32_t> DerivationPathStorage::get(size_t maxSize) const
{
	std::vector<uint32_t> result;

	for (const std::string& path : m_paths) {

		size_t pos = result.size();
		if (pos < maxSize)
			result.push_back(0);
		else
			assert(false);

		size_t offsetPrev = size_t(-1);
		
		do {
			offsetPrev++;
			size_t offsetCurr = path.find('/', offsetPrev);
			size_t count = ((offsetCurr == std::string::npos) ? (offsetCurr) : (offsetCurr - offsetPrev));
			std::string sub = path.substr(offsetPrev, count);
			offsetPrev = offsetCurr;

			if (sub == "m" || sub.empty())
				continue;

			uint32_t i;
			if (sub.back() == '\'') {
				sub.pop_back();
				i = std::stoi(sub);
				i += (1u << 31);
			}
			else {
				i = std::stoi(sub);
			}

			if (result.size() < maxSize) {
				result.push_back(i);
				result.at(pos)++;
			}
			else
				assert(false);

		} while (offsetPrev != std::string::npos);
	}

	return result;
}
