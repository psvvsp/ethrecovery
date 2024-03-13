#pragma once

#include <string>


struct Params
{
    Params()
        : mnemonicLength(0)
    {}

    bool validate(std::ostream& out) const;
    void print(std::ostream& out) const;
    void printCudaDevices(std::ostream& out) const;

    void dumpProgress(size_t skip) const;
    void restoreFromFile(int& argc, char**& argv);

    std::string address;
    std::string addressdb;
    std::string wordlistFile;
    std::string mnemonic;
    size_t mnemonicLength;
    std::string missingPositions;
    unsigned addrsToGenerate;
    unsigned addressStartIndex;
    size_t skip;
    int cudaDevice;

    static std::string s_addressOption;
    static std::string s_addressdbOption;
    static std::string s_wordlistFileOption;
    static std::string s_mnemonicOption;
    static std::string s_mnemonicLengthOption;
    static std::string s_missingPositionsOption;
    static std::string s_addrsToGenerateOption;
    static std::string s_addressStartIndexOption;
    static std::string s_skipOption;
    static std::string s_cudaDeviceOption;
};
