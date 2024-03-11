#pragma once

#include "params.h"

enum class Wallet
{
	BITCOIN,
	ETHEREUM,
};


std::string mnemrecover(const Params& params, Wallet wallet);
