#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

class Dictionary
{
public:
	Dictionary(const std::string &filename);
	bool getId(std::size_t &id, const std::string& word) const;
	bool getWord(std::size_t id, std::string& word) const;
	std::size_t sizePow() const;
	std::vector<uint8_t> get(std::size_t wordSizeMax) const;

private:
	std::map<std::string, std::size_t> m_words;
};
