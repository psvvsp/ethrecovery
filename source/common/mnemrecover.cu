#include "mnemrecover.h"

#include "addressdb.h"
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

#include "ripemd160.h"
#include "base58.h"
#include "bech32.h"

#include "uni_algo/norm.h"

#include <bitset>
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#define MAX_WORD_LENGTH 31
#define MAX_MNEMONIC_LENGTH 24
#define MAX_POSITIONS_NUMBER 10626
#define DERIVATION_PATH_BUFFER_COUNT 128
#define ADDRESS_LENGTH_ETH 20
#define ADDRESS_LENGTH_BTC 34
#define THREADS_PER_BLOCK 256

__constant__  __align__(4) uint16_t s_mnemonics[MAX_MNEMONIC_LENGTH];
__constant__ uint32_t s_positions[MAX_POSITIONS_NUMBER];
__constant__  __align__(4) uint8_t s_salt[8] = { 'm', 'n', 'e', 'm', 'o', 'n', 'i', 'c' };
__constant__  __align__(4) uint8_t s_seed[128] = { 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'};
__constant__ secp256k1_t s_basepoint;
__constant__ uint32_t s_derivation_path_buffer[DERIVATION_PATH_BUFFER_COUNT];
__constant__ uint32_t s_generator_order[8] = {
	0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xbaaedce6, 0xaf48a03b, 0xbfd25e8c, 0xd0364141
};
__constant__ __align__(4) uint8_t s_address[ADDRESS_LENGTH_BTC];

__host__ __device__ void printBuffer(const uint8_t* buffer, uint32_t size)
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

template<uint32_t DICTIONARY_POW, uint32_t MNEMONIC_LENGTH>
__global__ void ethrecover_checksum_kernel(
	uint64_t offset,
	uint64_t mnemNum,
	uint32_t mnemonicNumber,
	uint32_t posNum,
	uint64_t * mnemIds,
	uint32_t *resultNum)
{
	uint32_t gapSize = MNEMONIC_LENGTH - mnemonicNumber;
	uint64_t mnemId = offset + blockIdx.x*blockDim.x + threadIdx.x;

	if (mnemId >= mnemNum)
		return;

	uint32_t posId = mnemId % posNum;
	mnemId /= posNum;

	uint16_t wordIds[4];

	for (uint32_t i = 0; i < gapSize; i++) {
		wordIds[i] = mnemId & ((1 << DICTIONARY_POW) - 1);
		mnemId = mnemId >> DICTIONARY_POW;
	}

	uint32_t pos = s_positions[posId];
	uint8_t* posArr = reinterpret_cast<uint8_t*>(&pos);

	EntropyBuffer<DICTIONARY_POW, MNEMONIC_LENGTH> entropyBuffer;

	uint32_t j = 0, k = 0;
	for (uint32_t i = 0; i < MNEMONIC_LENGTH; i++) {
		if (j < gapSize && posArr[j] == i) {
			entropyBuffer.append(wordIds[j]);
			j++;
		}
		else {
			entropyBuffer.append(s_mnemonics[k]);
			k++;
		}
	}

	const uint32_t* data = reinterpret_cast<const uint32_t*>(entropyBuffer.entropyBytesData());
	int len = static_cast<int>(entropyBuffer.entropyBytesSize());

	sha256_ctx_t ctx256;
	sha256_init(&ctx256);
	sha256_update_swap(&ctx256, data, len);
	sha256_final(&ctx256);

	uint32_t checkSum1 = reinterpret_cast<uint8_t*>(ctx256.h)[3]
		>> (8 - EntropyBuffer<DICTIONARY_POW, MNEMONIC_LENGTH>::checksum_bit_size);

	uint32_t checkSum2 = entropyBuffer.checkSum();

	//if (wordIds[0] == 788) {
	//	printf("mnemId = %llu\n", offset + blockIdx.x * blockDim.x + threadIdx.x);
	//	printBuffer(entropyBuffer.entropyBytesData(), entropyBuffer.entropyBytesSize());
	//	printBuffer(reinterpret_cast<uint8_t*>(ctx256.h), 32);
	//	printf("checkSum1 = %u, checkSum2 = %u\n", checkSum1, checkSum2);
	//}

	if (checkSum1 == checkSum2) {
		uint32_t resultId = atomicAdd(resultNum, 1);
		mnemIds[resultId] = offset + blockIdx.x * blockDim.x + threadIdx.x;
	}
}

static __device__ bool findInDatabase(const uint8_t* address, const uint64_t* database, const AddressDbParams &params)
{
	uint32_t hash_bytes = hc_swap32_S(*reinterpret_cast<const uint32_t*>(address + 16));
	uint32_t position = hash_bytes & params.hash_mask;
	//uint64_t addr_to_find = hc_swap64_S(*reinterpret_cast<const uint64_t*>(address + 4));
	uint64_t addr_to_find; memcpy(&addr_to_find, address + 8, 8);

	while (true) {
		uint64_t cur_addr = database[position];
		if (cur_addr == 0)
			return false;
		if (cur_addr == addr_to_find)
			return true;
		position++;
		if (position == params.table_bytes / 8)
			position = 0;
	}

	return false;
}

struct Result 
{
	uint32_t addressIdx;
	uint32_t derPathIdx;
	uint64_t mnemonic;
};

template<uint32_t DICTIONARY_POW, uint32_t MNEMONIC_LENGTH>
//__launch_bounds__(THREADS_PER_BLOCK, 3)
__global__ void ethrecover_kernel(
	Wallet wallet,
	uint64_t* mnemIds,
	uint32_t* mnemIdsNum,
	uint32_t mnemonicNumber,
	uint32_t posNum,
	uint32_t addressStartIndex,
	uint32_t addrsToGenerate,
	Result *resultGPU,
	const uint8_t *dictionary,
	const uint64_t *addressDb,
	AddressDbParams addressDbParams)
{
	__shared__ uint32_t mnemIdsNumShared;
	if (threadIdx.x == 0) {
		mnemIdsNumShared = *mnemIdsNum;
	}
	__syncthreads();

	uint32_t gapSize = MNEMONIC_LENGTH - mnemonicNumber;
	uint32_t id = blockIdx.x * blockDim.x + threadIdx.x;

	for (; id < mnemIdsNumShared; id += blockDim.x*gridDim.x) {

		uint64_t mnemId = mnemIds[id];
		uint32_t posId = mnemId % posNum;

		uint32_t pos = s_positions[posId];
		uint8_t* posArr = reinterpret_cast<uint8_t*>(&pos);
		uint64_t mnemIdCopy = mnemId / posNum;

		uint16_t wordIds[4];
		for (uint32_t i = 0; i < gapSize; i++) {
			wordIds[i] = mnemIdCopy & ((1 << DICTIONARY_POW) - 1);
			mnemIdCopy = mnemIdCopy >> DICTIONARY_POW;
		}

		MnemBuilder<MNEMONIC_LENGTH, MAX_WORD_LENGTH> mnemBuilder(dictionary, 1 << DICTIONARY_POW);

		uint32_t j = 0, k = 0;
		for (uint32_t i = 0; i < MNEMONIC_LENGTH; i++) {
			if (j < gapSize && posArr[j] == i) {
				mnemBuilder.add(wordIds[j]);
				j++;
			}
			else {
				mnemBuilder.add(s_mnemonics[k]);
				k++;
			}
		}

		//__device__ void pbkdf2(
		//	const word * inbuffer, word inbufferSizeBytes,
		//	const word * saltbuffer, word * outbuffer,
		//	unsigned int iters, unsigned int dkLen_bytes);

		uint64_t result[8] = { 0 };
		pbkdf2(mnemBuilder.mnemo(), mnemBuilder.mnemoSizeBytes(),
			reinterpret_cast<const uint64_t*>(s_salt), 8, result,	2048, 64);

		const uint8_t* word = dictionary + (MAX_WORD_LENGTH + 1) * wordIds[0];
		//if (word[0] == 'g' && word[1] == 'u' && word[2] == 'a' && word[3] == 'r')
		//{
		//	printf("%s\n", word);
		//	printBuffer(reinterpret_cast<uint8_t*>(result), 64);
		//}

		//if (mnemId == 1237) {
		//	printf("wordIds[0] = %d, posArr[0] = %d\n", int(wordIds[0]), int(posArr[0]));
		//}

		//if (wordIds[0] == 1551 && posArr[0] == MNEMONIC_LENGTH - 1) {
		//	printBuffer(reinterpret_cast<uint8_t*>(result), 64);
		//}

		sha512_hmac_ctx ctx512;
		sha512_hmac_init_swap(&ctx512, reinterpret_cast<const uint32_t*>(s_seed), 12);
		sha512_hmac_update_swap(&ctx512, reinterpret_cast<uint32_t*>(result), 64);
		sha512_hmac_final(&ctx512);

		__shared__ uint64_t h[THREADS_PER_BLOCK][8];
		for (int i = 0; i < 8; i++)
			h[threadIdx.x][i] = hc_swap64_S(ctx512.opad.h[i]);

		//if (word[0] == 'g' && word[1] == 'u' && word[2] == 'a' && word[3] == 'r')
		//{
		//	printf("h = ");
		//	printBuffer(reinterpret_cast<uint8_t*>(h), 64);
		//}
		
		//if (wordIds[0] == 1551) {
		//	printBuffer(reinterpret_cast<uint8_t*>(h), 64);
		//}

		uint32_t I = 0;
		uint32_t current_path_index_length = s_derivation_path_buffer[I++];
		
		for (uint32_t k = 0; current_path_index_length != 0; k++) {

			uint32_t privkey_bytes[8];
			memcpy(privkey_bytes, h[threadIdx.x], 32);

			uint32_t chaincode_bytes[8] = { 0 };
			memcpy(chaincode_bytes, h[threadIdx.x] + 4, 32);

			for (uint32_t i = I; i < I + current_path_index_length; i++) {

				uint32_t idx = s_derivation_path_buffer[i];
				uint32_t hmac_data[16] = { 0 };

				if (idx < 2147483648u) {
					private_to_public(privkey_bytes, hmac_data);
				}
				else {
					memcpy(reinterpret_cast<uint8_t*>(hmac_data) + 1, privkey_bytes, 32);
				}
				uint32_t tmp = hc_swap32_S(idx);
				memcpy(reinterpret_cast<uint8_t*>(hmac_data) + 33, &tmp, 4);

				//if (word[0] == 'g' && word[1] == 'u' && word[2] == 'a' && word[3] == 'r')
				//{
				//	printf("%u, hmac_data = \n", idx);
				//	printBuffer(reinterpret_cast<uint8_t*>(hmac_data), 37);
				//}
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

			//if (word[0] == 'g' && word[1] == 'u' && word[2] == 'a' && word[3] == 'r')
			//{
			//	printf("privkey_bytes = ");
			//	printBuffer(reinterpret_cast<uint8_t*>(privkey_bytes), 32);

			//	printf("chaincode_bytes = ");
			//	printBuffer(reinterpret_cast<uint8_t*>(chaincode_bytes), 32);
			//}

			uint32_t hmac_data[16] = { 0 };
			private_to_public(privkey_bytes, hmac_data);

			//if (wordIds[0] == 1551) {
			//	printf("\n XXXXXXXXXXXXXXXXXXXXX hmac_data = \n");
			//	printBuffer(reinterpret_cast<uint8_t*>(hmac_data), 33);
			//}

			for (int i = 0; i < 8; i++)
				privkey_bytes[i] = hc_swap32_S(privkey_bytes[i]);

			BigInteger<8> privkey_int(privkey_bytes);

			for (uint32_t j = addressStartIndex; j < addressStartIndex + addrsToGenerate; j++) {

				uint32_t tmp = hc_swap32_S(j);
				memcpy(reinterpret_cast<uint8_t*>(hmac_data) + 33, &tmp, 4);

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

				//if (word[0] == 'g' && word[1] == 'u' && word[2] == 'a' && word[3] == 'r')
				//{
				//	printf("\n XXXXXXXXXXXXXXXXXXXXXXXXX d_privkey_bytes = \n");
				//	printBuffer(reinterpret_cast<uint8_t*>(d_privkey_bytes), 32);
				//}

				//if (wordIds[0] == 1237 && posArr[0] == mnemonicNumber) {
				//	printf("\n XXXXXXXXXXXXXXXXXXXXXXXXX d_privkey_bytes = \n");
				//	printBuffer(reinterpret_cast<uint8_t*>(d_privkey_bytes), 32);
				//}

				uint32_t d_pubkey[16] = { 0 };
				private_to_public_full(d_privkey_bytes, d_pubkey);


				//if (word[0] == 'g' && word[1] == 'u' && word[2] == 'a' && word[3] == 'r')
				//{
				//	printf("\n XXXXXXXXXXXXXXXXXXXXXXXXX d_pubkey = \n");
				//	printBuffer(reinterpret_cast<uint8_t*>(d_pubkey), 64);
				//}

				//if (wordIds[0] == 1237 && posArr[0] == mnemonicNumber) {
				//	printf("\n XXXXXXXXXXXXXXXXXXXXXXXXX d_pubkey = \n");
				//	printBuffer(reinterpret_cast<uint8_t*>(d_pubkey), 64);
				//}

				bool equal = true;

				if (wallet == Wallet::ETHEREUM)
				{
					uint32_t r[8];
					keccak256(r, d_pubkey, 64);

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

					if (!addressDb) {
						for (int i = 0; i < 5; i++)
							if (addressWords[i] != addressWordsTest[i])
								equal = false;
					}
					else {
						//printf("XXX");
						equal = findInDatabase(reinterpret_cast<const uint8_t*>(addressWordsTest), addressDb, addressDbParams);
					}
				}
				else if (wallet == Wallet::BITCOIN)
				{
					uint32_t compressed_pubkey[16] = { 0 };
					reinterpret_cast<uint8_t*>(compressed_pubkey)[0] = (reinterpret_cast<uint8_t*>(d_pubkey)[63] & 0x01) + 2;
					memcpy(reinterpret_cast<uint8_t*>(compressed_pubkey) + 1, d_pubkey, 32);

					sha256_ctx_t sha256_ctx;
					sha256_init(&sha256_ctx);
					sha256_update_swap(&sha256_ctx, compressed_pubkey, 33);
					sha256_final(&sha256_ctx);

					uint32_t hh[8];
					for (int i = 0; i < 8; i++)
						hh[i] = hc_swap32_S(sha256_ctx.h[i]);

					uint32_t ripe_digest[5];
					ripemd160(reinterpret_cast<uint8_t*>(hh), 32, reinterpret_cast<uint8_t *>(ripe_digest));

					//if (word[0] == 'g' && word[1] == 'u' && word[2] == 'a' && word[3] == 'r')
					//{
					//	printf("\n XXXXXXXXXXXXXXXXXXXXXXXXX compressed_pubkey = \n");
					//	printBuffer(reinterpret_cast<uint8_t*>(compressed_pubkey), 33);

					//	printf("\n XXXXXXXXXXXXXXXXXXXXXXXXX hh = \n");
					//	printBuffer(reinterpret_cast<uint8_t*>(hh), 32);

					//	printf("\n ripe_digest = \n");
					//	printBuffer(reinterpret_cast<uint8_t*>(ripe_digest), 20);
					//}

					if (!addressDb) {
						const uint32_t* addressWords = reinterpret_cast<uint32_t*>(s_address);
						for (int i = 0; i < 5; i++)
							if (addressWords[i] != ripe_digest[i])
								equal = false;
					}
					else {
						equal = findInDatabase(reinterpret_cast<const uint8_t*>(ripe_digest), addressDb, addressDbParams);
					}

				}

				if (equal) {
					resultGPU->derPathIdx = k;
					resultGPU->addressIdx = j;
					resultGPU->mnemonic = mnemId;
				}
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

	printBuffer(entropy_bytes.data(), entropy_bytes.size());
	printBuffer(digest, 32);

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

static std::vector<std::string> split(const std::string &str)
{
	std::vector<std::string> result;

	std::stringstream ss(str);

	while (true) {
		std::string s;
		ss >> s;
		if (ss)	result.push_back(s);
		else break;
	}

	return result;
}

static std::set<size_t> parseMissingPositions(const std::string missingPositions, size_t mnemonicLength)
{
	std::set<size_t> result;
	
	std::vector<std::string> v = split(missingPositions);

	for (const std::string& s : v) {
		size_t pos = std::stoi(s);
		if (pos >= mnemonicLength)
			std::cout << "Warning: invalid missing word position " << pos << std::endl;
		else
			result.insert(pos);
	}
	
	return result;
}

static bool convertBits(const std::vector<uint8_t>& data,
	uint32_t frombits, uint32_t tobits, std::vector<uint8_t> &result)
{
	uint32_t acc = 0;
	uint32_t bits = 0;
	uint32_t maxv = (1 << tobits) - 1;
	uint32_t max_acc = (1 << (frombits + tobits - 1)) - 1;

	for (uint8_t value : data)
	{
		if (value >> frombits)
			return false;
		acc = ((acc << frombits) | value) & max_acc;
		bits += frombits;
		while (bits >= tobits)
		{
			bits -= tobits;
			result.push_back((acc >> bits) & maxv);
		}
	}

	if (bits >= frombits || ((acc << (tobits - bits)) & maxv))
		return false;

	return true;
}

static bool setAddress(const Params& params, Wallet wallet)
{
	if (wallet == Wallet::ETHEREUM && params.address.size() == 2*ADDRESS_LENGTH_ETH)
	{
		std::vector<uint8_t> addressBuffer(ADDRESS_LENGTH_ETH);
		for (size_t i = 0; i < ADDRESS_LENGTH_ETH; i++)
		{
			std::string byte = params.address.substr(2 * i + 2, 2);
			addressBuffer.at(i) = std::stoi(byte, nullptr, 16);
		}
		CUDA_CALL(cudaMemcpyToSymbol(s_address, addressBuffer.data(), addressBuffer.size()));
		return true;
	}
	else if (wallet == Wallet::BITCOIN && params.address.size() == 34)
	{
		std::vector<uint8_t> address;
		if (!decodeBase58(params.address.data(), address))
			return false;

		address.erase(address.begin() + 21, address.end());
		address.erase(address.begin());

		assert(address.size() == ADDRESS_LENGTH_ETH);

		CUDA_CALL(cudaMemcpyToSymbol(s_address, address.data(), address.size()));
		return true;
	}
	else if (wallet == Wallet::BITCOIN && params.address.size() == 42)
	{
		bech32::DecodedResult decodedResult = bech32::decode(params.address);
		if (decodedResult.encoding == bech32::Encoding::Invalid)
			return false;

		decodedResult.dp.erase(decodedResult.dp.begin());

		std::vector<uint8_t> address;
		if (!convertBits(decodedResult.dp, 5, 8, address))
			return false;

		assert(address.size() == ADDRESS_LENGTH_ETH);

		CUDA_CALL(cudaMemcpyToSymbol(s_address, address.data(), address.size()));
		return true;
	}
	return false;

}

std::string mnemrecover(const Params& params, Wallet wallet)
{
	std::string normalized_mnemonic = una::norm::to_nfkd_utf8(params.mnemonic);
	std::vector<std::string> mnemonicVector = split(normalized_mnemonic);
	if (mnemonicVector.size() >= params.mnemonicLength)
		return params.mnemonic;

	for(std::string &word : mnemonicVector)
		word = una::norm::to_nfkd_utf8(word);


	size_t gapSize = params.mnemonicLength - mnemonicVector.size();
	std::set<size_t> missingPositions = parseMissingPositions(params.missingPositions, params.mnemonicLength);

	Dictionary dict(params.wordlistFile);

	//verify_checksum(dict, mnemonicVector);

	PosGen posGen(unsigned(params.mnemonicLength), unsigned(gapSize), missingPositions);
	std::vector<unsigned> positions = posGen.gen();

	std::vector<uint16_t> mnemonics(mnemonicVector.size());
	for (size_t i = 0; i < mnemonicVector.size(); i++) {
		size_t id;
		if (!dict.getId(id, mnemonicVector.at(i)))
		{
			std::cout << "\"" << mnemonicVector.at(i) << "\" is not in the wordlist" << std::endl;
			return std::string();
		}
		mnemonics.at(i) = static_cast<uint16_t>(id);
	}

	Result* result = nullptr;
	CUDA_CALL(cudaMalloc(&result, sizeof(Result)));
	CUDA_CALL(cudaMemset(result, 0xff, sizeof(Result)));

	CUDA_CALL(cudaMemcpyToSymbol(s_mnemonics, mnemonics.data(), mnemonics.size() * sizeof(uint16_t)));
	CUDA_CALL(cudaMemcpyToSymbol(s_positions, positions.data(), positions.size() * sizeof(uint32_t)));

	uint8_t* dictionaryGPU = nullptr;
	std::vector<uint8_t> dictBuffer = dict.get(MAX_WORD_LENGTH);

	CUDA_CALL(cudaMalloc(&dictionaryGPU, dictBuffer.size()));
	CUDA_CALL(cudaMemcpy(dictionaryGPU, dictBuffer.data(), dictBuffer.size(), cudaMemcpyHostToDevice));

	secp256k1_t basepoint;
	set_precomputed_basepoint_g(&basepoint);
	CUDA_CALL(cudaMemcpyToSymbol(s_basepoint, &basepoint, sizeof(basepoint)));

	DerivationPathStorage dps(wallet);
	std::vector<uint32_t> derivationPathBuffer = dps.get(DERIVATION_PATH_BUFFER_COUNT);
	derivationPathBuffer.resize(DERIVATION_PATH_BUFFER_COUNT, 0);
	CUDA_CALL(cudaMemcpyToSymbol(s_derivation_path_buffer, derivationPathBuffer.data(), derivationPathBuffer.size()*sizeof(uint32_t)));

	uint64_t *addressDbPtr = nullptr;
	AddressDbParams addressDbParams;

	if (!params.address.empty()) {
		if (!setAddress(params, wallet))
		{
			std::cout << "Invalid address" << std::endl;
			return std::string();
		}
	} 
	else {
		AddressDb addressDb(params.addressdb);
		if (!addressDb.success()) {
			std::cout << "Failed to read addresses database" << std::endl;
			return std::string();
		}
		
		const std::vector<char>& db = addressDb.getData();
		
		CUDA_CALL(cudaMalloc(&addressDbPtr, db.size()));
		CUDA_CALL(cudaMemcpy(addressDbPtr, db.data(), db.size(), cudaMemcpyHostToDevice));

		addressDbParams = addressDb.getParams();
	}

	uint32_t* mnemIdsNum = nullptr;
	CUDA_CALL(cudaMalloc(&mnemIdsNum, sizeof(uint32_t)));

	unsigned threadsPerBlock = THREADS_PER_BLOCK;
	
	size_t mnemNum = 1;
	for (size_t i = 0; i < gapSize; i++)
		mnemNum *= (size_t(1) << dict.sizePow());
	mnemNum *= positions.size();

	std::cout << "Number of mnemonics to check: " << mnemNum << std::endl;
	std::cout << std::endl;

	const unsigned blocksPerGrid = 1024;
	const unsigned threadsPerGrid = threadsPerBlock * blocksPerGrid;

	size_t numLaunches = ((mnemNum - params.skip)+ threadsPerGrid - 1) / threadsPerGrid;

	uint64_t* mnemIds = nullptr;
	size_t mnemIdsNumMax = 16 * threadsPerGrid;
	CUDA_CALL(cudaMalloc(&mnemIds, mnemIdsNumMax*sizeof(uint64_t)));

	Result resultCPU;

	CUDA_CALL(cudaMemset(mnemIdsNum, 0x00, sizeof(uint32_t)));

	using namespace std::chrono;
	steady_clock::time_point begin = steady_clock::now();
	steady_clock::time_point beginFile = begin;

	for (size_t launch = 0; launch < numLaunches; launch++) {
		
		size_t offset = params.skip + launch * threadsPerGrid;

		if (dict.sizePow() == 11 && params.mnemonicLength == 12) {

			//template<uint32_t DICTIONARY_POW, uint32_t MNEMONIC_LENGTH>
			//__global__ void ethrecover_checksum_kernel(
			//	uint64_t offset,
			//	uint64_t mnemNum,
			//	uint32_t mnemonicNumber,
			//	uint32_t posNum,
			//	uint64_t * mnemIds,
			//	uint32_t * resultNum)

			ethrecover_checksum_kernel<11, 12> << <blocksPerGrid, threadsPerBlock >> > (
				offset,
				mnemNum,
				static_cast<uint32_t>(mnemonics.size()),
				static_cast<uint32_t>(positions.size()),
				mnemIds,
				mnemIdsNum);
		}
		else if (dict.sizePow() == 11 && params.mnemonicLength == 24) {
			
			ethrecover_checksum_kernel<11, 24> << <blocksPerGrid, threadsPerBlock >> > (
				offset,
				mnemNum,
				static_cast<uint32_t>(mnemonics.size()),
				static_cast<uint32_t>(positions.size()),
				mnemIds,
				mnemIdsNum);
		}
		else {
			assert(false);
		}

		CUDA_CALL(cudaGetLastError());
		CUDA_CALL(cudaDeviceSynchronize());

		if (((launch > 0) && (launch % 16 == 0)) || launch == numLaunches - 1) {

			if (dict.sizePow() == 11 && params.mnemonicLength == 12) {

				//__global__ void ethrecover_kernel(
				//  Wallet wallet,
				//	uint64_t * mnemIds,
				//	uint32_t * mnemIdsNum,
				//	uint32_t mnemonicNumber,
				//	uint32_t posNum,
				//	uint32_t addressStartIndex,
				//	uint32_t addrsToGenerate,
				//	Result * resultGPU,
				//	const uint8_t * dictionary,
				//  const uint64_t* addressDb,
			    //  AddressDbParams addressDbParams)
				//	)

				ethrecover_kernel<11, 12> << <blocksPerGrid, threadsPerBlock >> > (
					wallet,
					mnemIds,
					mnemIdsNum,
					static_cast<uint32_t>(mnemonics.size()),
					static_cast<uint32_t>(positions.size()),
					params.addressStartIndex,
					params.addrsToGenerate,
					result,
					dictionaryGPU,
					addressDbPtr,
					addressDbParams);
			}
			else if (dict.sizePow() == 11 && params.mnemonicLength == 24) {

				ethrecover_kernel<11, 24> << <blocksPerGrid, threadsPerBlock >> > (
					wallet,
					mnemIds,
					mnemIdsNum,
					static_cast<uint32_t>(mnemonics.size()),
					static_cast<uint32_t>(positions.size()),
					params.addressStartIndex,
					params.addrsToGenerate,
					result,
					dictionaryGPU,
					addressDbPtr,
					addressDbParams);
			}
			else {
				assert(false);
			}

			CUDA_CALL(cudaGetLastError());
			CUDA_CALL(cudaDeviceSynchronize());

			CUDA_CALL(cudaMemcpy(&resultCPU, result, sizeof(Result), cudaMemcpyDeviceToHost));

			if (resultCPU.mnemonic != uint64_t(-1))
				break;

			CUDA_CALL(cudaMemset(mnemIdsNum, 0x00, sizeof(uint32_t)));

			std::cout << "Processed " << offset << " mnemonics";
			if (launch > 0) {
				steady_clock::time_point end = steady_clock::now();
				auto time_span = duration_cast<duration<double>>(end - begin);
				std::cout << " (" << 16*size_t(threadsPerGrid / time_span.count()) << " mnemos/s)";
				//std::cout << " (" << time_span.count() << " seconds)";
				begin = end;

				time_span = duration_cast<duration<double>>(end - beginFile);
				if (time_span.count() > 60.0) {
					params.dumpProgress(offset);
					beginFile = end;
				}
			}
			std::cout << "\r";
		}
	}

	std::cout << std::string(80, ' ') << std::endl;

	if (resultCPU.mnemonic == uint64_t(-1))
		return std::string();

	uint32_t posId = uint32_t(resultCPU.mnemonic % positions.size());
	uint32_t pos = positions.at(posId);

	uint64_t blockIdx = resultCPU.mnemonic / positions.size();

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

	uint32_t j = 0, k = 0;
	for (size_t i = 0; i < params.mnemonicLength; i++) {
		if (j < gapSize && posArr[j] == i) {
			mnemonic.append(" " + words.at(j));
			j++;
		}
		else {
			mnemonic.append(" " + mnemonicVector.at(k));
			k++;
		}
	}
	mnemonic.erase(0, 1);

	mnemonic = dps.at(resultCPU.derPathIdx) + "/" + std::to_string(resultCPU.addressIdx) + ": " + mnemonic;

	return mnemonic;
}