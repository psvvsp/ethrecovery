#include "CLI/CLI.hpp"

#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
//using namespace std;

int main(int argc, char* argv[])
{
    CLI::App app("Tests utility");

    std::string fileInput;
    std::string fileOutput;

    app.add_option("--input-file, -i", fileInput, "File with commands")->required(false)->default_val("tests.txt");
    app.add_option("--output-file, -o", fileOutput, "File with test report")->required(false)->default_val("test_report.txt");

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

    std::ifstream fin(fileInput);
    if (!fin)
    {
        std::cout << "Failed to open file: " << fileInput << std::endl;
        return EXIT_FAILURE;
    }

    std::ofstream fout(fileOutput);
    if (!fout)
    {
        std::cout << "Failed to open file: " << fileOutput << std::endl;
        return EXIT_FAILURE;
    }

    int passed = 0;
    int failed = 0;

    int testId = 0;
    std::string command;

    while (std::getline(fin, command))
    {
        int retcode = system(command.c_str());
        if (retcode != EXIT_SUCCESS)
        {
            failed++;
            fout << testId << ". failed: " << command << std::endl;
            fout << "\tcommand return code: " << retcode << std::endl;
        }
        else
        {
            std::ifstream fresult("result.txt");
            std::stringstream buffer;
            buffer << fresult.rdbuf();
            if (!buffer.str().find("Result:"))
            {
                failed++;
                fout << testId << ". failed: " << command << std::endl;
                fout << "\tcommand output:\n" << buffer.str() << std::endl;
            }
            else
            {
                passed++;
                fout << testId << ". passed: " << command << std::endl;
            }
        }

        std::ofstream fresult("result.txt");
        testId++;
    }

    fout << "====================================================" << std::endl;
    fout << passed << " tests passed, " << failed << " tests failed" << std::endl;

	return EXIT_SUCCESS;
}