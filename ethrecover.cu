#include "ethrecover.h"

#include "dictionary.h"
#include "entbuffer.cuh"
#include "posgen.h"
#include "utils.h"

#include "sha256/SHA256.h"

#include <bitset>
#include <iostream>
#include <sstream>

#define MAX_MNEMONIC_LENGTH 24
#define MAX_POSITIONS_NUMBER 10000

__constant__ uint16_t s_mnemonics[MAX_MNEMONIC_LENGTH];
__constant__ uint32_t s_positions[MAX_POSITIONS_NUMBER];

template<uint32_t DICTIONARY_POW, uint32_t MNEMONIC_LENGTH>
__global__ void ethrecover_kernel(
	uint32_t mnemonicNumber,
	uint32_t posNum)
{
	__shared__ uint16_t wordIds[4];

	uint32_t gapSize = MNEMONIC_LENGTH - mnemonicNumber;

	if (threadIdx.x == 0) {
		uint32_t blockId = blockIdx.x;
		for (uint32_t i = 0; i < gapSize; i++) {
			wordIds[i] = blockId & ((1 << DICTIONARY_POW) - 1);
			blockId = blockId >> DICTIONARY_POW;
		}
	}

	__syncthreads();

	for (uint32_t posId = threadIdx.x; posId < posNum; posId += blockDim.x) {

		uint32_t pos = s_positions[posId];
		uint8_t* posArr = reinterpret_cast<uint8_t*>(&pos);

		EntropyBuffer<DICTIONARY_POW, MNEMONIC_LENGTH> entropyBuffer;

		uint32_t j = 0;
		for (uint32_t i = 0; i < mnemonicNumber; i++) {
			while (j < gapSize && posArr[j] == i) {
				entropyBuffer.append(wordIds[j]);
				j++;
			}
			entropyBuffer.append(s_mnemonics[i]);
		}
		while (j < gapSize && posArr[j] == mnemonicNumber) {
			entropyBuffer.append(wordIds[j]);
			j++;
		}


	}

}

static bool verify_checksum(
	const Dictionary &dict,
	const std::vector<std::string>& mnemonicVector)
{
	std::ostringstream bits;
	for (const std::string& word : mnemonicVector) {
		size_t id;
		if (!dict.getId(id, word))
			return false;
		bits << std::bitset<11>(id);
	}

	std::string bit_string = bits.str();

	size_t cksum_len_in_bits = mnemonicVector.size() / 3;
	std::vector<uint8_t> entropy_bytes;

	for (size_t i = 0; i < bit_string.length() - cksum_len_in_bits; i += 8) {
		std::string sub = bit_string.substr(i, 8);
		entropy_bytes.push_back(uint8_t(std::stoi(sub, nullptr, 2)));
	}

	std::string sub = bit_string.substr(bit_string.length() - cksum_len_in_bits);
	size_t cksum_int = size_t(std::stoi(sub, nullptr, 2));

	SHA256 hasher;
	hasher.update(entropy_bytes.data(), entropy_bytes.size());
	uint8_t *digest = hasher.digest();

	uint8_t candidate = digest[0] >> 8 - cksum_len_in_bits;

	delete[] digest;
	return candidate == cksum_int;
}

static bool verify_checksum_gpu(
	const Dictionary& dict,
	const std::vector<std::string>& mnemonicVector)
{
	std::ostringstream bits;
	EntropyBuffer<11, 12> buf;

	const uint8_t* data = buf.entropyBytesData();
	const uint32_t size = buf.entropyBytesSize();

	for (const std::string& word : mnemonicVector) {
		size_t id;
		if (!dict.getId(id, word))
			return false;
		buf.append(uint32_t(id));
		
		std::cout << id << " " << std::bitset<11>(id) << std::endl;
		bits << std::bitset<11>(id);

		for (size_t i = 0; i < size; i++) {
			std::cout << std::bitset<8>(data[i]);
		}
		std::cout << std::endl;
		std::cout << bits.str() << std::endl;
	}

	for (size_t i = 0; i < size; i++) {
		bits << std::bitset<8>(data[i]);
	}

	SHA256 hasher;
	hasher.update(buf.entropyBytesData(), buf.entropyBytesSize());
	uint8_t* digest = hasher.digest();

	size_t cksum_len_in_bits = mnemonicVector.size() / 3;
	uint8_t candidate = digest[0] >> 8 - cksum_len_in_bits;

	delete[] digest;
	return candidate == buf.checkSum();
}

std::string ethrecover(const Params& params)
{
	std::vector<std::string> mnemonicVector;
	std::stringstream ss(params.mnemonic);

	while (true) {
		std::string s;
		ss >> s;
		if (ss)	mnemonicVector.push_back(s);
		else break;
	}

	//if (mnemonicVector.size() >= params.mnemonicLength)
	//	return params.mnemonic;

	//PosGen posGen(unsigned(params.mnemonicLength), unsigned(params.mnemonicLength - mnemonicVector.size()));
	//std::vector<unsigned> positions = posGen.gen();

	Dictionary dict(params.language);

	verify_checksum(dict, mnemonicVector);
	verify_checksum_gpu(dict, mnemonicVector);



	return std::string();
}