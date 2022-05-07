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

    bool validate(std::ostream& out) const;
    void dumpProgress(size_t skip) const;
    void restoreFromFile(int& argc, char**& argv);

    std::string address;
    std::string addressdb;
    std::string mnemonic;
    size_t mnemonicLength;
    Language language;
    std::string missingPositions;
    unsigned addrsToGenerate;
    unsigned addressStartIndex;
    size_t skip;

    static std::string s_addressOption;
    static std::string s_addressdbOption;
    static std::string s_mnemonicOption;
    static std::string s_mnemonicLengthOption;
    static std::string s_missingPositionsOption;
    static std::string s_addrsToGenerateOption;
    static std::string s_addressStartIndexOption;
    static std::string s_skipOption;
};
