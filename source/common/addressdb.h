#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct AddressDbParams
{
	uint64_t table_bytes = 0;
	uint32_t bytes_per_addr = 0;
	uint32_t hash_bytes = 0;
	uint32_t hash_mask = 0;
};

class AddressDb
{
public:
	AddressDb(const std::string &filename);
	const AddressDbParams& getParams() const { return m_params; }
	const std::vector<char>& getData() const { return m_data; }
	bool success() const { return m_success; }

private:
	bool m_success;
	AddressDbParams m_params;
	std::vector<char> m_data;
};