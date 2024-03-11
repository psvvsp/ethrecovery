#pragma once

#include <map>
#include <string>
#include <vector>

class Dictionary
{
public:
	Dictionary(const std::string &filename);
	bool getId(size_t &id, const std::string& word) const;
	bool getWord(size_t id, std::string& word) const;
	size_t sizePow() const;
	std::vector<uint8_t> get(size_t wordSizeMax) const;

private:
	std::map<std::string, size_t> m_words;
};