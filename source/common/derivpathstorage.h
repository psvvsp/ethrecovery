#pragma once

#include "mnemrecover.h"

#include <cstdint>
#include <string>
#include <vector>

class DerivationPathStorage
{
public:
	DerivationPathStorage(Wallet wallet);
	std::vector<uint32_t> get(std::size_t maxSize) const;
	std::string at(std::size_t i) const { return m_paths.at(i); }

private:
	std::vector<std::string> m_paths;
};