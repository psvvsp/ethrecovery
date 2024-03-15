#pragma once

#include "params.h"

#include <iostream>

enum class Wallet
{
	BITCOIN,
	ETHEREUM,
};


std::string mnemrecover(const Params& params, Wallet wallet);

std::string mnemrecover_stream(std::istream &in, const Params& params, Wallet wallet);
