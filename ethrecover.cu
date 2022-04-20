#include "ethrecover.h"

#include "biginteger.cuh"
#include "derivpathstorage.h"
#include "dictionary.h"
#include "entbuffer.cuh"
#include "keccak256.cuh"
#include "mnembuilder.cuh"
#include "pbkdf2.h"
#include "posgen.h"
#include "utils.h"

#include "sha256/SHA256.h"

#include <cstdint>

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_sha256.h"
#include "inc_hash_sha512.h"
#include "inc_ecc_secp256k1.h"

#include <bitset>
#include <iostream>
#include <sstream>
#include <vector>

#define MAX_WORD_LENGTH 15
#define MAX_MNEMONIC_LENGTH 24
#define MAX_POSITIONS_NUMBER 10000
#define DERIVATION_PATH_BUFFER_COUNT 128
#define ADDRESS_LENGTH 20

__constant__ uint16_t s_mnemonics[MAX_MNEMONIC_LENGTH];
__constant__ uint32_t s_positions[MAX_POSITIONS_NUMBER];
__constant__ uint8_t s_salt[8] = { 'm', 'n', 'e', 'm', 'o', 'n', 'i', 'c' };
__constant__ uint8_t s_seed[128] = { 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'};
__constant__ secp256k1_t s_basepoint;
__constant__ uint32_t s_derivation_path_buffer[DERIVATION_PATH_BUFFER_COUNT];
__constant__ uint32_t s_generator_order[8] = {
	0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xbaaedce6, 0xaf48a03b, 0xbfd25e8c, 0xd0364141
};
__constant__ uint8_t s_address[ADDRESS_LENGTH];

__device__ void printBuffer(const uint8_t* buffer, uint32_t size)
{
	for (uint32_t i = 0; i < size; i++)
		printf("%02x", uint32_t(buffer[i]));
	printf("\n");
}

__device__ void private_to_public(const uint32_t* pri, uint32_t* pub)
{
	uint32_t a[8];
	for (int i = 0; i < 8; i++)
		a[i] = hc_swap32_S(pri[7 - i]);

	point_mul(pub, a, &s_basepoint);

	for (int i = 0; i < 9; i++)
		pub[i] = hc_swap32_S(pub[i]);
}

__device__ void private_to_public_full(const uint32_t* pri, uint32_t* pub)
{
	uint32_t a[8];
	for (int i = 0; i < 8; i++)
		a[i] = hc_swap32_S(pri[7 - i]);

	uint32_t x[8], y[8];

	point_mul_xy(x, y, a, &s_basepoint);

	for (int i = 0; i < 8; i++)
		pub[i] = hc_swap32_S(x[7 - i]);

	for (int i = 0; i < 8; i++)
		pub[i + 8] = hc_swap32_S(y[7 - i]);
}

struct MnemonicDescription
{
	uint32_t pos; 
	uint32_t blockId;
};

template<uint32_t DICTIONARY_POW, uint32_t MNEMONIC_LENGTH>
__global__ void ethrecover_checksum_kernel(
	uint32_t offset,
	uint32_t mnemonicNumber,
	uint32_t posNum,
	MnemonicDescription* result,
	uint32_t *resultNum)
{
	__shared__ uint16_t wordIds[4];

	uint32_t gapSize = MNEMONIC_LENGTH - mnemonicNumber;

	if (threadIdx.x == 0) {
		uint32_t blockId = blockIdx.x + offset;
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

		const uint32_t* data = reinterpret_cast<const uint32_t*>(entropyBuffer.entropyBytesData());
		int len = static_cast<int>(entropyBuffer.entropyBytesSize() >> 2);

		sha256_ctx_t ctx256;
		sha256_init(&ctx256);
		sha256_update(&ctx256, data, len);
		sha256_final(&ctx256);

		uint32_t checkSum1 = reinterpret_cast<uint8_t*>(ctx256.h)[0]
			>> (8 - EntropyBuffer<DICTIONARY_POW, MNEMONIC_LENGTH>::checksum_bit_size);

		uint32_t checkSum2 = entropyBuffer.checkSum();

		//if (wordIds[0] == 1237 && posArr[0] == mnemonicNumber) {
		//	printf("checkSum1 = %u, checkSum2 = %u\n", checkSum1, checkSum2);
		//}

		if (checkSum1 == checkSum2) {
			uint32_t resultId = atomicAdd(resultNum, 1);
			
			MnemonicDescription descr;
			descr.pos = pos;
			descr.blockId = blockIdx.x + offset;

			result[resultId] = descr;
		}
	}
}


template<uint32_t DICTIONARY_POW, uint32_t MNEMONIC_LENGTH>
__global__ void ethrecover_kernel(
	MnemonicDescription* mnemonicDescr,
	uint32_t* mnemonicDescrNum,
	uint32_t mnemonicNumber,
	uint32_t posNum,
	uint64_t *resultGPU,
	const uint8_t *dictionary)
{
	__shared__ uint32_t mnemDescrNumShared;
	if (threadIdx.x) {
		mnemDescrNumShared = *mnemonicDescrNum;
	}
	__syncthreads();

	uint32_t gapSize = MNEMONIC_LENGTH - mnemonicNumber;

	uint32_t id = blockIdx.x * blockDim.x + threadIdx.x;
	for (; id < mnemDescrNumShared; id += blockDim.x*gridDim.x) {

		MnemonicDescription mnemDescr = mnemonicDescr[id];

		uint32_t blockId = mnemDescr.blockId;
		uint8_t* posArr = reinterpret_cast<uint8_t*>(&mnemDescr.pos);

		uint16_t wordIds[4];
		for (uint32_t i = 0; i < gapSize; i++) {
			wordIds[i] = blockId & ((1 << DICTIONARY_POW) - 1);
			blockId = blockId >> DICTIONARY_POW;
		}

		MnemBuilder<MNEMONIC_LENGTH, MAX_WORD_LENGTH> mnemBuilder(dictionary, 1 << DICTIONARY_POW);

		uint32_t j = 0;
		for (uint32_t i = 0; i < mnemonicNumber; i++) {
			while (j < gapSize && posArr[j] == i) {
				mnemBuilder.add(wordIds[j]);
				j++;
			}
			mnemBuilder.add(s_mnemonics[i]);
		}
		while (j < gapSize && posArr[j] == mnemonicNumber) {
			mnemBuilder.add(wordIds[j]);
			j++;
		}

		//__device__ void pbkdf2(
		//	const word * inbuffer, word inbufferSizeBytes,
		//	const word * saltbuffer, word * outbuffer,
		//	unsigned int iters, unsigned int dkLen_bytes);

		uint64_t result[16] = { 0 };
		pbkdf2(mnemBuilder.mnemo(), mnemBuilder.mnemoSizeBytes(),
			reinterpret_cast<const uint64_t*>(s_salt), 8, result,	2048, 64);

		//if (wordIds[0] == 1237 && posArr[0] == mnemonicNumber) {
		//	printBuffer(reinterpret_cast<uint8_t*>(result), 64);
		//}

		sha512_hmac_ctx ctx512;
		sha512_hmac_init_swap(&ctx512, reinterpret_cast<const uint32_t*>(s_seed), 12);
		sha512_hmac_update_swap(&ctx512, reinterpret_cast<uint32_t*>(result), 64);
		sha512_hmac_final(&ctx512);

		uint64_t h[8];
		for (int i = 0; i < 8; i++)
			h[i] = hc_swap64_S(ctx512.opad.h[i]);

		//if (wordIds[0] == 1237 && posArr[0] == mnemonicNumber) {
		//	printBuffer(reinterpret_cast<uint8_t*>(h), 64);
		//}

		uint32_t I = 0;
		uint32_t current_path_index_length = s_derivation_path_buffer[I++];
		
		while (current_path_index_length != 0) {

			uint32_t privkey_bytes[8];
			memcpy(privkey_bytes, h, 32);

			uint32_t chaincode_bytes[32] = { 0 };
			memcpy(chaincode_bytes, h + 4, 32);

			for (uint32_t i = I; i < I + current_path_index_length; i++) {

				uint32_t idx = s_derivation_path_buffer[i];
				uint32_t hmac_data[32] = { 0 };

				if (idx < 2147483648u) {
					private_to_public(privkey_bytes, hmac_data);
				}
				else {
					memcpy(reinterpret_cast<uint8_t*>(hmac_data) + 1, privkey_bytes, 32);
				}
				uint32_t tmp = hc_swap32_S(idx);
				memcpy(reinterpret_cast<uint8_t*>(hmac_data) + 33, &tmp, 4);

				//if (wordIds[0] == 1237 && posArr[0] == mnemonicNumber) {
				//	printf("%u, hmac_data = \n", idx);
				//	printBuffer(reinterpret_cast<uint8_t*>(hmac_data), 37);
				//	//printf("%u, basepoint = \n", idx);
				//	//printBuffer(reinterpret_cast<uint8_t*>(s_basepoint.xy), 4 * 96);
				//}

				sha512_hmac_init_swap(&ctx512, chaincode_bytes, 32);
				sha512_hmac_update_swap(&ctx512, hmac_data, 37);
				sha512_hmac_final(&ctx512);

				for (int i = 0; i < 8; i++)
					ctx512.opad.h[i] = hc_swap64_S(ctx512.opad.h[i]);

				//if (wordIds[0] == 1237 && posArr[0] == mnemonicNumber) {
				//	printf("%u, opad = \n", idx);
				//	printBuffer(reinterpret_cast<uint8_t*>(ctx512.opad.h), 64);
				//	printf("%u, a = \n", idx);
				//	printBuffer(reinterpret_cast<uint8_t*>(ctx512.opad.h), 32);
				//	printf("%u, b = \n", idx);
				//	printBuffer(reinterpret_cast<uint8_t*>(privkey_bytes), 32);
				//}

				uint32_t* bytes = reinterpret_cast<uint32_t*>(ctx512.opad.h);
				for (int i = 0; i < 8; i++)
					bytes[i] = hc_swap32_S(bytes[i]);

				BigInteger<8> bigInt1(reinterpret_cast<uint32_t*>(ctx512.opad.h));
				
				for (int i = 0; i < 8; i++)
					privkey_bytes[i] = hc_swap32_S(privkey_bytes[i]);

				BigInteger<8> bigInt2(privkey_bytes);
				bigInt1 += bigInt2;
				
				BigInteger<8> bigInt3(s_generator_order);
				bigInt1.mod(bigInt3);

				memcpy(privkey_bytes, bigInt1.get(), 32);
				memcpy(chaincode_bytes, ctx512.opad.h + 4, 32);

				for (int i = 0; i < 8; i++)
					privkey_bytes[i] = hc_swap32_S(privkey_bytes[i]);

				//if (wordIds[0] == 1237 && posArr[0] == mnemonicNumber) {
				//	printf("%u, c = \n", idx);
				//	printBuffer(reinterpret_cast<uint8_t*>(privkey_bytes), 32);
				//}
			}

			uint32_t hmac_data[32] = { 0 };
			private_to_public(privkey_bytes, hmac_data);

			//if (wordIds[0] == 1237 && posArr[0] == mnemonicNumber) {
			//	printf("\n XXXXXXXXXXXXXXXXXXXXX hmac_data = \n");
			//	printBuffer(reinterpret_cast<uint8_t*>(hmac_data), 33);
			//}

			for (int i = 0; i < 8; i++)
				privkey_bytes[i] = hc_swap32_S(privkey_bytes[i]);

			BigInteger<8> privkey_int(privkey_bytes);

			//memcpy(reinterpret_cast<uint8_t*>(hmac_data) + 33, s_address, ADDRESS_LENGTH);

			sha512_hmac_init_swap(&ctx512, chaincode_bytes, 32);
			sha512_hmac_update_swap(&ctx512, hmac_data, 37);
			sha512_hmac_final(&ctx512);

			uint64_t h[8];
			for (int i = 0; i < 8; i++)
				h[i] = hc_swap64_S(ctx512.opad.h[i]);

			//if (wordIds[0] == 1237 && posArr[0] == mnemonicNumber) {
			//	printf("\n XXXXXXXXXXXXXXXXXXXXXXXXX h = \n");
			//	printBuffer(reinterpret_cast<uint8_t*>(h), 64);
			//}

			for (int i = 0; i < 8; i++)
				reinterpret_cast<uint32_t*>(h)[i] = hc_swap32_S(reinterpret_cast<uint32_t*>(h)[i]);

			BigInteger<8> bigInt(reinterpret_cast<uint32_t*>(h));
			bigInt += privkey_int;

			BigInteger<8> bigInt3(s_generator_order);
			bigInt.mod(bigInt3);

			uint32_t d_privkey_bytes[8];
			memcpy(d_privkey_bytes, bigInt.get(), 32);

			for (int i = 0; i < 8; i++)
				d_privkey_bytes[i] = hc_swap32_S(d_privkey_bytes[i]);

			//if (wordIds[0] == 1237 && posArr[0] == mnemonicNumber) {
			//	printf("\n XXXXXXXXXXXXXXXXXXXXXXXXX d_privkey_bytes = \n");
			//	printBuffer(reinterpret_cast<uint8_t*>(d_privkey_bytes), 32);
			//}

			uint32_t d_pubkey[32] = { 0 };
			private_to_public_full(d_privkey_bytes, d_pubkey);

			//if (wordIds[0] == 1237 && posArr[0] == mnemonicNumber) {
			//	printf("\n XXXXXXXXXXXXXXXXXXXXXXXXX d_pubkey = \n");
			//	printBuffer(reinterpret_cast<uint8_t*>(d_pubkey), 64);
			//}

			uint32_t r[8];
			keccak256(r, d_pubkey, 64);

			bool equal = true;

			const uint32_t* addressWords = reinterpret_cast<uint32_t*>(s_address);
			//const uint32_t* addressWordsTest = reinterpret_cast<uint32_t*>(d_ctx512.h) + 11;
			const uint32_t* addressWordsTest = r + 3;

			//if (wordIds[0] == 1237 && posArr[0] == mnemonicNumber) {
			//	printf("\n XXXXXXXXXXXXXXXXXXXXXXXXX addressWords = \n");
			//	printBuffer(reinterpret_cast<const uint8_t *>(addressWords), 20);

			//	printf("\n XXXXXXXXXXXXXXXXXXXXXXXXX addressWordsTest = \n");
			//	printBuffer(reinterpret_cast<const uint8_t*>(addressWordsTest), 20);

			//	printf("\n XXXXXXXXXXXXXXXXXXXXXXXXX r = \n");
			//	printBuffer(reinterpret_cast<const uint8_t*>(r), 32);
			//}


			for (int i = 0; i < 5; i++)
				if (addressWords[i] != addressWordsTest[i])
					equal = false;

			if (equal) {
				//printf("\n FOUND!!!\n");
				uint64_t f = (uint64_t(mnemDescr.blockId) << 32) | mnemDescr.pos;
				*resultGPU = f;
			}

			I += current_path_index_length;
			current_path_index_length = s_derivation_path_buffer[I++];
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

//static bool verify_checksum_gpu(
//	const Dictionary& dict,
//	const std::vector<std::string>& mnemonicVector)
//{
//	std::ostringstream bits;
//	EntropyBuffer<11, 12> buf;
//
//	const uint8_t* data = buf.entropyBytesData();
//	const uint32_t size = buf.entropyBytesSize();
//
//	for (const std::string& word : mnemonicVector) {
//		size_t id;
//		if (!dict.getId(id, word))
//			return false;
//		buf.append(uint32_t(id));
//		
//		std::cout << id << " " << std::bitset<11>(id) << std::endl;
//		bits << std::bitset<11>(id);
//
//		for (size_t i = 0; i < size; i++) {
//			std::cout << std::bitset<8>(data[i]);
//		}
//		std::cout << std::endl;
//		std::cout << bits.str() << std::endl;
//	}
//
//	for (size_t i = 0; i < size; i++) {
//		bits << std::bitset<8>(data[i]);
//	}
//
//	SHA256 hasher;
//	hasher.update(buf.entropyBytesData(), buf.entropyBytesSize());
//	uint8_t* digest = hasher.digest();
//
//	size_t cksum_len_in_bits = mnemonicVector.size() / 3;
//	uint8_t candidate = digest[0] >> 8 - cksum_len_in_bits;
//
//	delete[] digest;
//	return candidate == buf.checkSum();
//}

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

	if (mnemonicVector.size() >= params.mnemonicLength)
		return params.mnemonic;

	size_t gapSize = params.mnemonicLength - mnemonicVector.size();

	PosGen posGen(unsigned(params.mnemonicLength), unsigned(gapSize));
	std::vector<unsigned> positions = posGen.gen();

	Dictionary dict(params.language);

	std::vector<uint16_t> mnemonics(mnemonicVector.size());
	for (size_t i = 0; i < mnemonicVector.size(); i++) {
		size_t id;
		if (!dict.getId(id, mnemonicVector.at(i)))
			return std::string();
		mnemonics.at(i) = static_cast<uint16_t>(id);
	}

	uint64_t* result = nullptr;
	CUDA_CALL(cudaMalloc(&result, sizeof(uint64_t)));
	CUDA_CALL(cudaMemset(result, 0xff, sizeof(uint64_t)));

	CUDA_CALL(cudaMemcpyToSymbol(s_mnemonics, mnemonics.data(), mnemonics.size() * sizeof(uint16_t)));
	CUDA_CALL(cudaMemcpyToSymbol(s_positions, positions.data(), positions.size() * sizeof(uint32_t)));

	uint8_t* dictionaryGPU = nullptr;
	std::vector<uint8_t> dictBuffer = dict.get(MAX_WORD_LENGTH);

	CUDA_CALL(cudaMalloc(&dictionaryGPU, dictBuffer.size()));
	CUDA_CALL(cudaMemcpy(dictionaryGPU, dictBuffer.data(), dictBuffer.size(), cudaMemcpyHostToDevice));

	secp256k1_t basepoint;
	set_precomputed_basepoint_g(&basepoint);
	CUDA_CALL(cudaMemcpyToSymbol(s_basepoint, &basepoint, sizeof(basepoint)));

	DerivationPathStorage dps;
	std::vector<uint32_t> derivationPathBuffer = dps.get(DERIVATION_PATH_BUFFER_COUNT);
	derivationPathBuffer.resize(DERIVATION_PATH_BUFFER_COUNT, 0);
	CUDA_CALL(cudaMemcpyToSymbol(s_derivation_path_buffer, derivationPathBuffer.data(), derivationPathBuffer.size()*sizeof(uint32_t)));

	std::vector<uint8_t> addressBuffer(ADDRESS_LENGTH);
	for (size_t i = 0; i < ADDRESS_LENGTH; i++) {
		std::string byte = params.address.substr(2 * i + 2, 2);
		addressBuffer.at(i) = std::stoi(byte, nullptr, 16);
	}
	CUDA_CALL(cudaMemcpyToSymbol(s_address, addressBuffer.data(), addressBuffer.size()));

	uint32_t* mnemonicDescriptionNum = nullptr;
	CUDA_CALL(cudaMalloc(&mnemonicDescriptionNum, sizeof(uint32_t)));

	unsigned threadsPerBlock = 256;
	
	unsigned blocksPerGrid = 1;
	for (size_t i = 0; i < gapSize; i++)
		blocksPerGrid *= (1 << dict.sizePow());

	std::cout << "Number of mnemonics to check: " << blocksPerGrid * positions.size() << std::endl;

	const unsigned blocksPerGridMax = 1024;
	unsigned numLaunches = (blocksPerGrid + blocksPerGridMax - 1) / 1024;

	MnemonicDescription* mnemonicDescription = nullptr;
	size_t mnemonicDescriptionNumMax = 16 * blocksPerGridMax * positions.size();
	CUDA_CALL(cudaMalloc(&mnemonicDescription, mnemonicDescriptionNumMax*sizeof(MnemonicDescription)));

	uint64_t resultCPU = uint64_t(-1);

	CUDA_CALL(cudaMemset(mnemonicDescriptionNum, 0x00, sizeof(uint32_t)));

	for (unsigned launch = 0; launch < numLaunches; launch++) {
		
		unsigned offset = launch * blocksPerGridMax;
		unsigned blocksPerGridLaunch = std::min(blocksPerGridMax, blocksPerGrid - offset);

		if (dict.sizePow() == 11 && params.mnemonicLength == 12) {

			//__global__ void ethrecover_checksum_kernel(
			//	uint32_t offset,
			//	uint32_t mnemonicNumber,
			//	uint32_t posNum,
			//	MnemonicDescription * result,
			//	uint32_t * resultNum)

			ethrecover_checksum_kernel<11, 12> << <blocksPerGridLaunch, threadsPerBlock >> > (
				offset,
				static_cast<uint32_t>(mnemonics.size()),
				static_cast<uint32_t>(positions.size()),
				mnemonicDescription,
				mnemonicDescriptionNum);
		}
		else {
			assert(false);
		}

		CUDA_CALL(cudaGetLastError());
		CUDA_CALL(cudaDeviceSynchronize());

		if (((launch > 0) && (launch % 16 == 0)) || launch == numLaunches - 1) {

			if (dict.sizePow() == 11 && params.mnemonicLength == 12) {
				//__global__ void ethrecover_kernel(
				//	MnemonicDescription * mnemonicDescr,
				//	uint32_t * mnemonicDescrNum,
				//	uint32_t mnemonicNumber,
				//	uint32_t posNum,
				//	uint64_t * resultGPU,
				//	const uint8_t * dictionary)

				ethrecover_kernel<11, 12> << <blocksPerGridMax, threadsPerBlock >> > (
					mnemonicDescription,
					mnemonicDescriptionNum,
					static_cast<uint32_t>(mnemonics.size()),
					static_cast<uint32_t>(positions.size()),
					result,
					dictionaryGPU);
			}
			else {
				assert(false);
			}

			CUDA_CALL(cudaGetLastError());
			CUDA_CALL(cudaDeviceSynchronize());

			CUDA_CALL(cudaMemcpy(&resultCPU, result, sizeof(uint64_t), cudaMemcpyDeviceToHost));

			if (resultCPU != uint64_t(-1))
				break;

			CUDA_CALL(cudaMemset(mnemonicDescriptionNum, 0x00, sizeof(uint32_t)));

			std::cout << "Processed " << (offset + blocksPerGridLaunch) * positions.size() << " mnemonics\r";
		}
	}

	if (resultCPU == uint64_t(-1))
		return std::string();

	uint32_t blockIdx = resultCPU >> 32;
	uint32_t pos = resultCPU & 0xffffffff;

	std::vector<std::string> words(gapSize);
	const size_t DICTIONARY_POW = dict.sizePow();

	for (size_t i = 0; i < gapSize; i++) {
		size_t wordId = blockIdx & ((1 << DICTIONARY_POW) - 1);
		std::string word;
		bool success = dict.getWord(wordId, word);
		assert(success);
		words.at(i) = word;
		blockIdx = blockIdx >> DICTIONARY_POW;
	}

	std::string mnemonic;
	const uint8_t* posArr = reinterpret_cast<uint8_t*>(&pos);

	uint32_t j = 0;
	for (size_t i = 0; i < mnemonicVector.size(); i++) {
		while (j < gapSize && posArr[j] == i) {
			mnemonic.append(" " + words.at(j));
			j++;
		}
		mnemonic.append(" " + mnemonicVector.at(i));
	}
	while (j < gapSize && posArr[j] == mnemonicVector.size()) {
		mnemonic.append(" " + words.at(j));
		j++;
	}
	mnemonic.erase(0, 1);

	return mnemonic;
}