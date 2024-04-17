#include "MD5.hpp"

#include <chrono>
#include <iostream>
#include <iterator>
#include <vector>
#include <numeric>

std::string MD5::md5Gen(const std::string &input)
{
    // https://p...content-available-to-author-only...s.org/besson/publis/notebooks/Manual_implementation_of_some_hash_functions.html na C++
    using u64 = uint64_t;
    using u32 = uint32_t;
    using u8 = uint8_t;

    auto leftrotate = [&](unsigned x, int c) { return ((x << c) | (x >> (32 - c))); };

    const int s[64] = {7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 5,  9,  14, 20, 5,  9,
                       14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23,
                       4,  11, 16, 23, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21};
    const u32 K[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1,
        0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453,
        0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942,
        0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
        0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

    unsigned a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

    std::vector<u8> data;
    copy(input.begin(), input.end(), std::back_inserter(data));
    u64 orig_len = input.size() * 8;
    data.push_back(0x80);
    while (data.size() % 64 != 56)
    {
        data.push_back(0);
    }
    for (int i = 0; i < 8; ++i)
    {
        data.push_back(orig_len & 0xFF);
        orig_len >>= 8;
    }

    for (size_t offset = 0; offset < data.size(); offset += 64)
    {
        unsigned A = a0, B = b0, C = c0, D = d0;
        const u8 *chunk = data.data() + offset;
        for (int i = 0; i < 64; ++i)
        {
            unsigned F, g;
            if (i < 16)
            {
                F = ((B & C) | ((~B) & D));
                g = i;
            }
            else if (i < 32)
            {
                F = ((B & D) | (C & (~D)));
                g = (5 * i + 1) % 16;
            }
            else if (i < 48)
            {
                F = B ^ C ^ D;
                g = (3 * i + 5) % 16;
            }
            else
            {
                F = (C ^ (B | (~D)));
                g = (7 * i) % 16;
            }
            const u8 *dword = chunk + (4 * g);
            unsigned x = (((((dword[3] << 8) | dword[2]) << 8) | dword[1]) << 8) | dword[0];
            unsigned r = A + F + K[i] + x;
            A = D;
            D = C;
            C = B;
            B += leftrotate(r, s[i]);
        }
        a0 += A;
        b0 += B;
        c0 += C;
        d0 += D;
    }

    const std::string hex = "0123456789abcdef";
    std::string result;
    for (u32 e : {a0, b0, c0, d0})
    {
        for (int i = 0; i < 4; ++i)
        {
            result += hex[(e >> 4) & 0xF];
            result += hex[e & 0xF];
            e >>= 8;
        }
    }
    return result;
}


std::string MD5::md5Crack(const std::string hash, const int threadCount, const int passwdLength)
{
    //print basic info
    if (verbose)
    {
        std::cout << "Thread count: " << threadCount << "\n";
        std::cout << "Password length: " << passwdLength << "\n";
    }

    // set class properties
    terminateThreads = false;
    lastPasswdReached = false;
    this->hash = hash;

    for (int i = 0; i < passwdLength; i++)
    {
        this->passwd.push_back(this->beginLetter);
        this->lastPasswd.push_back(this->endLetter);
    }


    // start threads
    for (int i = 0; i < threadCount; i++)
    {
        this->hashSpeed.push_back(0);
        this->threads.push_back(std::thread(&MD5::thread, this, i));
    }

    std::thread progressThread(&MD5::progress, this);


    for (auto &thread : this->threads)
    {
        thread.join();
    }
    progressThread.join();

    return this->foundPasswd;
}

int MD5::md5SpeedTest(const int threadCount, const int passwdLength)
{
    unsigned long long int speed = 0;
    const int timeBetweenMeasurements = 200; // in ms
    const int measurementsCount = 2 * 60 * 1000 / timeBetweenMeasurements; // 2 minutes

    // set class properties
    terminateThreads = false;
    lastPasswdReached = false;
    this->hash = "wrongHash";
    this->verbose = true;


    for (int i = 0; i < passwdLength; i++)
    {
        this->passwd.push_back(this->beginLetter);
        this->lastPasswd.push_back(this->endLetter);
    }

    // start threads
    for (int i = 0; i < threadCount; i++)
    {
        this->hashSpeed.push_back(0);
        this->threads.push_back(std::thread(&MD5::thread, this, i));
    }
    std::thread progressThread(&MD5::progress, this);

    for (auto &thread : this->threads)
    {
        thread.detach();
    }
    progressThread.detach();

    // sum up all measurements
    std::this_thread::sleep_for(std::chrono::milliseconds(500)); //wait for threads to start
    for (int i = 0; i < measurementsCount; i++)
    {
        speed += std::reduce(hashSpeed.begin(), hashSpeed.end());
        std::this_thread::sleep_for(std::chrono::milliseconds(timeBetweenMeasurements));

        if (this->lastPasswdReached)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(timeBetweenMeasurements));
            speed = speed / i;
            return speed;
        }
    }

    this->terminateThreads = true;
    speed = speed / measurementsCount;
    return speed;
}

void MD5::thread(const int threadId)
{
    std::vector<char> passwd;
    auto startTime = std::chrono::high_resolution_clock::now();

    while (true)
    {
        if (terminateThreads)
        {
            return;
        }

        if (lastPasswdReached) // not necessary to add mutex, because in worst case it will check one more password
        {
            return;
        }

        //get passwords set
        getPasswdMutex.lock();
        passwd = getPasswd();
        getPasswdMutex.unlock();

        startTime = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < this->passwdInThread; i++)
        {
            if (terminateThreads)
            {
                return;
            }


            // Check password
            std::string passwdStr(passwd.begin(), passwd.end());
            std::string hash = md5Gen(passwdStr);

            if (hash == this->hash)
            {
                this->foundPasswd = passwdStr;
                this->terminateThreads = true;
                return;
            }


            // Increase password
            if (lastPasswdReached) // check if last password reached
            {
                if (passwd == this->lastPasswd)
                {
                    return;
                }
            }

            passwd[0]++;
            for (int j = 0; j < static_cast<int>(passwd.size()); j++)
            {
                if (passwd[j] > this->endLetter)
                {
                    passwd[j] = this->beginLetter;
                    passwd[j + 1]++;
                }
                else
                {
                    break;
                }
            }
        }

        if (!lastPasswdReached)
        {
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
            hashSpeed[threadId] = this->passwdInThread * 1000 / duration;
        }
    }
}

std::vector<char> MD5::getPasswd()
{
    std::vector<char> currentPasswd = this->passwd;
    for (int i = 0; i < this->passwdInThread; i++)
    {
        this->passwd[0]++;
        for (int j = 0; j < static_cast<int>(this->passwd.size()); j++)
        {
            if (this->passwd[j] > this->endLetter)
            {
                if (j + 1 == static_cast<int>(this->passwd.size()))
                {
                    this->lastPasswdReached = true;

                    for (auto &letter : passwd)
                    {
                        letter = endLetter;
                    }
                    return currentPasswd;
                }

                this->passwd[j] = this->beginLetter;
                this->passwd[j + 1]++;
            }
            else
            {
                break;
            }
        }
    }

    return currentPasswd;
}


void MD5::progress()
{
    const int sleepTime = 100;

    if (!verbose)
    {
        return;
    }

    while (true)
    {
        std::cout << "Current password: " << std::string(passwd.begin(), passwd.end())
                  << "     Current speed: " << std::reduce(hashSpeed.begin(), hashSpeed.end())
                  << " hash/s\r";


        std::cout.flush();

        if (this->terminateThreads)
        {
            return;
        }

        if (this->lastPasswdReached)
        {
            return;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
    }
}


// Just incrementing one letter by one is enough efficient

// std::vector<char> MD5::getPasswd()
// {
//     std::vector<char> currentPasswd = this->passwd;
//     int passwdToIncrease = this->passwdInThread;

//     if (this->lastPasswdReached)
//     {
//         return {};
//     }

//     while (passwdToIncrease > 0)
//     {
//         for (int i = 0; i < passwd.size(); i++) // normal increase
//         {
//             if (endLetter - passwd[i] >= passwdToIncrease)
//             {
//                 passwd[i] += passwdToIncrease;
//                 passwdToIncrease = 0;
//                 break;
//             }

//             if ((passwd.size() - 1 == i) && (endLetter - passwd[i] < passwdToIncrease)) // finish when last password reached
//             {
//                 for (auto &letter : passwd)
//                 {
//                     letter = endLetter;
//                 }
//                 this->lastPasswdReached = true;
//                 passwdToIncrease = 0;
//                 break;
//             }

//             // It is necessary to change next letter
//             char letter = passwd[i];
//             passwd[i] = beginLetter + ((passwdToIncrease - (endLetter - passwd[i]) - 1) % (endLetter - beginLetter));
//             passwdToIncrease = ((passwdToIncrease - (endLetter - letter) + 1) / (endLetter - beginLetter));//wywalono jeden
//         }
//     }


//     return currentPasswd;
// }
