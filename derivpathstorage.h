#pragma once

#include <cstdint>
#include <string>
#include <vector>

class DerivationPathStorage
{
public:
	DerivationPathStorage();
	std::vector<uint32_t> get(size_t maxSize) const;

private:
	std::vector<std::string> m_paths;
};