#include "derivpathstorage.h"

#include <algorithm>
#include <cassert>
#include <fstream>
#include <iostream>

DerivationPathStorage::DerivationPathStorage(Wallet wallet)
{
	std::string filename;
	if (wallet == Wallet::BITCOIN)
		filename = "BTC.txt";
	else if (wallet == Wallet::ETHEREUM)
		filename = "ETH.txt";
	else
		assert(false);

	std::ifstream fin;
	fin.open("./derivationpath-lists/" + filename);

	if (!fin.is_open())
	{
		fin.open("./data/derivationpath-lists/" + filename);
		if (!fin.is_open())
			std::cout << "Failed to open derivation path lists file" << std::endl;
	}

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

std::vector<uint32_t> DerivationPathStorage::get(std::size_t maxSize) const
{
	std::vector<uint32_t> result;

	for (const std::string& path : m_paths) {

		std::size_t pos = result.size();
		if (pos < maxSize)
			result.push_back(0);
		else
			assert(false);

		std::size_t offsetPrev = std::size_t(-1);
		
		do {
			offsetPrev++;
			std::size_t offsetCurr = path.find('/', offsetPrev);
			std::size_t count = ((offsetCurr == std::string::npos) ? (offsetCurr) : (offsetCurr - offsetPrev));
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
