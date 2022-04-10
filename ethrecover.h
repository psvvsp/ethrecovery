#pragma once

#include <string>

enum class Language
{
    ENGLISH = 0
};

struct Params
{
    Params()
        : mnemonicLength(0)
        , language(Language::ENGLISH)
    {}

    std::string address;
    std::string mnemonic;
    size_t mnemonicLength;
    Language language;
};

std::string ethrecover(const Params& params);