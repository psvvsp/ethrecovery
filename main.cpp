#include "ethrecover.h"

#include "CLI/CLI.hpp"

#include <iostream>
#include <string>


int main(int argc, char* argv[])
{
    Params params;
    CLI::App app("Ethrecover - GPU Ethereum Wallet mnemonic recovery tool");

    app.add_option("--addrs", params.address, "Address in the wallet")->required(true);
    app.add_option("--mnemonic", params.mnemonic, "Your best guess of the mnemonic")->required(true);
    app.add_option("--mnemonic-length", params.mnemonicLength, "The length of the correct mnemonic")->check(CLI::Range(12, 24))->required(true);

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

    std::string mnemonic = ethrecover(params);
    if (mnemonic.empty())
    {
        std::cout << "Nothing found" << std::endl;
    }
    else
    {
        std::cout << "Found mnemonic: \"" << mnemonic << "\"" << std::endl;
    }

    return 0;
}