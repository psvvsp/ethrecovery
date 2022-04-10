#include "dictionary.h"

#include <cassert>
#include <fstream>
#include <vector>

Dictionary::Dictionary(Language language)
{
	std::string filename;
	
	if (language == Language::ENGLISH)
		//filename = "D:\\work\\Spring2022\\EthRecovery\\ethrecovery\\wordlists\\bip39-en.txt";
		filename = ".\\wordlists\\bip39-en.txt";
	else
		assert(false);

	std::ifstream fin(filename);

	for(size_t i = 0; ; i++) {
		std::string word;
		fin >> word;
		if (!fin) break;
		m_words.insert({ word, i });
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
