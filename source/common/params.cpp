#include "params.h"

#include "utils.h"

#include <fstream>
#include <string>
#include <vector>


static std::string s_progressFilename = "progress.txt";

std::string Params::s_addressOption = "--addrs";
std::string Params::s_addressdbOption = "--addressdb";
std::string Params::s_wordlistFileOption = "--wordlist-file";
std::string Params::s_mnemonicOption = "--mnemonic";
std::string Params::s_mnemonicLengthOption = "--mnemonic-length";
std::string Params::s_missingPositionsOption = "--missing-positions";
std::string Params::s_addrsToGenerateOption = "--addrs-to-generate";
std::string Params::s_addressStartIndexOption = "--address-start-index";
std::string Params::s_skipOption = "--skip";
std::string Params::s_cudaDeviceOption = "--cuda-device";
std::string Params::s_mnemonicFileOption = "--mnemonic-file";
std::string Params::s_mnemonicStdinFlag = "--mnemonic-stdin";


bool Params::validate(std::ostream &out) const
{
    if (address.empty() && addressdb.empty()) {
        out << "Both address and address database options are not specified" << std::endl;
        return false;
    }

    if (!mnemonicFile.empty() && mnemonicStdin) {
        out << "Both mnemonic file and mnemonic stdin are specified" << std::endl;
        return false;
    }

    if (cudaSetDevice(cudaDevice) != cudaError_t::cudaSuccess) {
        out << "Failed to set cuda device " << cudaDevice << ". "
            << "See help for the list of CUDA devices. " << std::endl;
        return false;
    }

    return true;
}

void Params::print(std::ostream& out) const
{
    out << std::endl;

    out << "Address: " << address << std::endl;
    out << "Address database: " << addressdb << std::endl;
    out << "Wordlist file: " << wordlistFile << std::endl;
    out << "Mnemonic: " << mnemonic << std::endl;
    out << "Mnemonic length: " << mnemonicLength << std::endl;
    out << "Missing positions: " << missingPositions << std::endl;
    out << "Addresses to generate: " << addrsToGenerate << std::endl;
    out << "Address start index: " << addressStartIndex << std::endl;
    out << "Skip: " << skip << std::endl;
    out << "Mnemonic file: " << mnemonicFile << std::endl;
    out << "Mnemonic stdin: " << mnemonicStdin << std::endl;
    out << "CUDA device id: " << cudaDevice << " ";

    cudaDeviceProp deviceProps;
    if (cudaGetDeviceProperties(&deviceProps, cudaDevice) == cudaError_t::cudaSuccess)
    {
        out << "(" << deviceProps.name << ")";
    }
    
    out << std::endl;
    out << std::endl;
}

void Params::printCudaDevices(std::ostream& out) const
{
    out << "Available CUDA devices:" << std::endl;

    int deviceCount;
    CUDA_CALL(cudaGetDeviceCount(&deviceCount));

    cudaDeviceProp deviceProps;
    for (int deviceId = 0; deviceId < deviceCount; deviceId++)
    {
        CUDA_CALL(cudaGetDeviceProperties(&deviceProps, deviceId));
        out << deviceId << " : " << deviceProps.name << std::endl;
    }
}

void Params::dumpProgress(size_t skip) const
{
    std::ofstream fout(s_progressFilename);

    fout << s_addressOption << " \"" << address << "\"" << std::endl;
    fout << s_addressdbOption << " \"" << addressdb << "\"" << std::endl;
    fout << s_wordlistFileOption << " \"" << wordlistFile << "\"" << std::endl;
    fout << s_mnemonicOption << " \"" << mnemonic << "\"" << std::endl;
    fout << s_mnemonicLengthOption << " \"" << mnemonicLength << "\"" << std::endl;
    fout << s_missingPositionsOption << " \"" << missingPositions << "\"" << std::endl;
    fout << s_addrsToGenerateOption << " \"" << addrsToGenerate << "\"" << std::endl;
    fout << s_addressStartIndexOption << " \"" << addressStartIndex << "\"" << std::endl;
    fout << s_skipOption << " \"" << skip << "\"" << std::endl;
    fout << s_cudaDeviceOption << " \"" << cudaDevice << "\"" << std::endl;
    fout << s_mnemonicFileOption << " \"" << mnemonicFile << "\"" << std::endl;
    fout << s_mnemonicStdinFlag << " \"" << mnemonicStdin << "\"" << std::endl;
}

void Params::restoreFromFile(int &argc, char **&argv)
{
    std::ifstream fin(s_progressFilename);

    if (!fin.is_open())
        return;

    std::vector<std::string> args(1 + 24);
    args.at(0) = "ethrecover.exe";

    for (size_t i = 0; i < args.size() / 2; i++) {
        
        std::string tmp;
        
        fin >> tmp;  
        args.at(2 * i + 1) = tmp;

        std::getline(fin, tmp, '\"');
        std::getline(fin, tmp, '\"');

        args.at(2 * i + 2) = tmp;
        std::getline(fin, tmp);
    }

    argc = int(args.size());
    argv = new char* [argc];
    
    for (int i = 0; i < argc; i++) {
        argv[i] = new char[args.at(i).size() + 1];
        memcpy(argv[i], args.at(i).c_str(), args.at(i).size());
        argv[i][args.at(i).size()] = '\0';
    }
}
