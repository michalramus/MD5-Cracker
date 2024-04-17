#include "MD5.hpp"

#include <iostream>
#include <string>

void crackPassword(const std::string hash, const int threadCount, const int passwdLength, const bool verbose);
void testSpeed(int passwdLength, std::vector<int> threadCounts);

int main(int argc, char *argv[])
{
    bool verbose = false;
    bool testSpeeds = false;
    int passwdLength = 0;
    int threadCount = 0;
    std::string hash = "";

    std::vector<std::string> arguments;

    // parse arguments
    for (int i = 1; i < argc; ++i)
    {
        std::string arg(argv[i]);
        arguments.push_back(arg);
    }

    // I know that this is not the best and most beautiful way to parse arguments, but it is enough:)
    for (auto &arg : arguments)
    {
        if (arg == "-v")
        {
            verbose = true;
            continue;
        }

        if (arg == "--test-speeds")
        {
            testSpeeds = true;
            continue;
        }

        if (testSpeeds)
        {
            if (!passwdLength)
            {
                try
                {
                    passwdLength = std::stoi(arg);
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Password length must be a number\n";
                    return EINVAL;
                }
                continue;
            }
        }
        else
        {
            if (!passwdLength)
            {
                try
                {
                    passwdLength = std::stoi(arg);
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Password length must be a number\n";
                    return EINVAL;
                }
                continue;
            }
            else if (hash.empty())
            {
                hash = arg;
                continue;
            }
            else if (!threadCount)
            {
                try
                {
                    threadCount = std::stoi(arg);
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Thread count must be a number\n";
                    return EINVAL;
                }
                continue;
            }
        }
    }

    if (testSpeeds)
    {
        testSpeed(passwdLength, {1, 2, 4, 8, 16, 32});
    }
    else
    {
        crackPassword(hash, threadCount, passwdLength, verbose);
    }

    return 0;
}

void crackPassword(const std::string hash, const int threadCount, const int passwdLength, const bool verbose)
{
    MD5 md5;
    md5.verbose = verbose;

    auto startTime = std::chrono::high_resolution_clock::now();

    std::string password = md5.md5Crack(hash, threadCount, passwdLength);

    auto endTime = std::chrono::high_resolution_clock::now();

    // reduce time to biggest possible unit
    std::string timeUnit = "s";
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime).count();
    if (duration > 60)
    {
        duration = std::chrono::duration_cast<std::chrono::minutes>(endTime - startTime).count();
        timeUnit = "m";
    }

    if (duration > 60)
    {
        duration = std::chrono::duration_cast<std::chrono::hours>(endTime - startTime).count();
        timeUnit = "h";
    }

    // print results
    if (password.empty())
    {
        if (verbose)
        {
            std::cout << "\n--------------------------------\n";
            std::cout << "Password not found\n";
            std::cout << "Time: " << duration << timeUnit << "\n";
        }
        else
        {
            std::cout << "BRAK";
        }
    }
    else
    {
        if (verbose)
        {
            std::cout << "\n--------------------------------\n";
            std::cout << "Time: " << duration << timeUnit << "\n";
            std::cout << "Password found: ";
        }
        std::cout << password << std::endl;
    }
}

/**
 * @brief Print average speed of cracking MD5 hash for each thread count
 * 
 * @param passwdLength 
 * @param threadCounts 
 */
void testSpeed(int passwdLength, std::vector<int> threadCounts)
{
    std::cout << "Testing speeds...\n";

    std::vector<int> speeds;

    // test speed for each thread count
    for (auto &threadCount : threadCounts)
    {
        std::cout << "\nTesting speed for " << threadCount << " threads...\n";
        MD5 md5;
        auto speed = md5.md5SpeedTest(threadCount, passwdLength);
        speeds.push_back(speed);
    }

    // print results
    std::cout << "--------------------------------\n";
    for (int i = 0; i < static_cast<int>(threadCounts.size()); ++i)
    {
        if (speeds[i] == 0)
        {
            std::cout << "Speed for " << threadCounts[i] << " threads: too short password\n";
            continue;
        }

        std::cout << "Speed for " << threadCounts[i] << " threads: " << speeds[i] << " hashes per second\n";
    }
}
