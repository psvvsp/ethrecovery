#include "dictionary.h"

#include "uni_algo/norm.h"

#include <cassert>
#include <fstream>
#include <iostream>
#include <vector>

Dictionary::Dictionary(const std::string& filename)
{
	std::ifstream fin(filename);

	if (!fin.is_open())
		std::cout << "Failed to open wordlist file" << std::endl;

	for(size_t i = 0; ; i++) {
		std::string word;
		fin >> word;
		if (!fin) break;
		
		// erase unicode marker
		if (word.size() >= 3 && word.at(0) == char(0xef) && word.at(1) == char(0xbb) && word.at(2) == char(0xbf))
			word.erase(0, 3);

		std::string normalized_word = una::norm::to_nfkd_utf8(word);
		m_words.insert({ normalized_word, i });
	}
}

bool Dictionary::getId(size_t& id, const std::string& word) const
{
	auto it = m_words.find(word);
	
	if (it == m_words.end())
		return false;

	id = it->second;
	return true;
}

bool Dictionary::getWord(size_t id, std::string& word) const
{
	for(const auto &pair : m_words)
		if (pair.second == id) {
			word = pair.first;
			return true;
		}

	return false;
}

size_t Dictionary::sizePow() const
{
	size_t size = m_words.size();
	assert((size & (size - 1)) == 0);

	size_t result = -1;
	while (size != 0) {
		size >>= 1;
		result++;
	}

	return result;
}

std::vector<uint8_t> Dictionary::get(size_t wordSizeMax) const
{
	std::vector<uint8_t> dict(m_words.size() * (wordSizeMax + 1));

	for (auto pair : m_words) {
		size_t id = pair.second;
		size_t offset = id * (wordSizeMax + 1);
		const std::string &word = pair.first;
		size_t size = word.size();
		assert(size <= wordSizeMax);
		for (size_t i = 0; i < size; i++)
			dict.at(offset + i) = word.at(i);
		for (size_t i = size; i < wordSizeMax + 1; i++)
			dict.at(offset + i) = '\0';
	}

	return dict;
}
