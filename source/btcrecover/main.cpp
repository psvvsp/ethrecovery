#include "mnemrecover.h"

#include "CLI/CLI.hpp"

#include <fstream>
#include <iostream>
#include <string>


static void printParams(std::ostream& out, const Params& params)
{
    out << "Address: " << params.address << std::endl;
    out << "Address database: " << params.addressdb << std::endl;
    out << "Wordlist file: " << params.wordlistFile << std::endl;
    out << "Mnemonic: " << params.mnemonic << std::endl;
    out << "Mnemonic length: " << params.mnemonicLength << std::endl;
    out << "Missing positions: " << params.missingPositions << std::endl;
    out << "Addresses to generate: " << params.addrsToGenerate << std::endl;
    out << "Address start index: " << params.addressStartIndex << std::endl;
    out << "Skip: " << params.skip << std::endl;
    out << std::endl;
}

static void printResult(std::ostream& out, const std::string& result)
{
    if (result.empty())
    {
        out << "Nothing found" << std::endl;
    }
    else
    {
        out << "Result: \"" << result << "\"" << std::endl;
    }
}

int main(int argc, char* argv[])
{
    Params params;

    if (argc == 1) {
        params.restoreFromFile(argc, argv);
    }

    CLI::App app("Btcrecover - GPU Bitcoin Wallet mnemonic recovery tool");

    app.add_option(Params::s_addressOption, params.address, "Address in the wallet")->required(false)->default_val("");
    app.add_option(Params::s_addressdbOption, params.addressdb, "Addresses database file")->required(false)->default_val("");
    app.add_option(Params::s_wordlistFileOption, params.wordlistFile, "Wordlist file")->required(false)->default_val("./wordlists/bip39-en.txt");
    app.add_option(Params::s_mnemonicOption, params.mnemonic, "Your best guess of the mnemonic")->required(true);
    app.add_option(Params::s_mnemonicLengthOption, params.mnemonicLength, "The length of the correct mnemonic")->check(CLI::Range(12, 24))->required(true);
    app.add_option(Params::s_missingPositionsOption, params.missingPositions, "Positions of missing words in the result mnemonic")->required(false);
    app.add_option(Params::s_addrsToGenerateOption, params.addrsToGenerate, "Number of addresses generated for each derivation path")->required(false)->default_val(1);
    app.add_option(Params::s_addressStartIndexOption, params.addressStartIndex, "Start addresses index")->required(false)->default_val(0);
    app.add_option(Params::s_skipOption, params.skip, "Skip several first mnemonics")->required(false)->default_val(0);

    try
    {
        app.parse(argc, argv);
    }
    catch (const CLI::CallForHelp& e)
    {
        return app.exit(e);
    }
    catch (const CLI::ParseError& e)
    {
        std::cout << e.what() << std::endl;
        return e.get_exit_code();
    }

    printParams(std::cout, params);
    if (!params.validate(std::cout)) {
        return 1;
    }

    params.dumpProgress(params.skip);

    std::string mnemonic = mnemrecover(params, Wallet::BITCOIN);

    printResult(std::cout, mnemonic);

    std::ofstream fout("result.txt");
    printParams(fout, params);
    printResult(fout, mnemonic);

    return 0;
}