#include "addressdb.h"

#include <fstream>

static const char s_magic[] = "seedrecover address database\r\n";
static size_t HEADER_LEN = 65536;

AddressDb::AddressDb(const std::string &filename)
{
	m_success = false;

	std::ifstream fin(filename, std::ios::binary);
	if (!fin) return;

	std::vector<char> header(HEADER_LEN);
	fin.read(header.data(), header.size());

	if (!fin) return;
	if (memcmp(header.data(), s_magic, sizeof(s_magic) - 1) != 0) 
		return;

	header.back() = '\0';

	char* beg = strchr(header.data(), '{') + 1;
	char* end = strchr(header.data(), '}') - 1;

	if (beg == nullptr || end == nullptr || end < beg) 
		return;

	std::string s(beg, end - beg + 1);
	
	while (true) {

		size_t pos = s.find_first_of(',');
		std::string elem = s.substr(0, pos);
		
		size_t del = elem.find_first_of(':');
		
		std::string key = elem.substr(0, del - 1);
		std::string val = elem.substr(del + 1);

		if (key.find("_table_bytes") != std::string::npos) {
			m_params.table_bytes = std::stoull(val);
		}
		else if (key.find("_bytes_per_addr") != std::string::npos) {
			m_params.bytes_per_addr = std::stoi(val);
		}
		else if (key.find("_hash_bytes") != std::string::npos) {
			m_params.hash_bytes = std::stoi(val);
		}
		else if (key.find("_hash_mask") != std::string::npos) {
			m_params.hash_mask = uint32_t(std::stoul(val));
		}

		s = s.substr(pos + 1);
		if (pos == std::string::npos)
			break;
	}

	if (m_params.bytes_per_addr != 8)
		return;

	if (m_params.hash_bytes != 4)
		return;

	if (m_params.table_bytes / m_params.bytes_per_addr != m_params.hash_mask + 1)
		return;

	m_data.resize(m_params.table_bytes);
	fin.read(m_data.data(), m_data.size());

	if (!fin) return;
	m_success = true;
}
