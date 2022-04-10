#pragma once

#include "ethrecover.h"

#include <map>
#include <string>

class Dictionary
{
public:
	Dictionary(Language language);
	bool getId(size_t &id, const std::string& word) const;

private:
	std::map<std::string, size_t> m_words;
};