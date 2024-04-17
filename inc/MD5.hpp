#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>


class MD5
{
public:
    /**
     * @brief Generate MD5 hash
     *
     * @param input
     * @return std::string
     */
    static std::string md5Gen(const std::string &input);

    /**
     * @brief
     *
     * @param hash
     * @param threadCount
     * @param passwdLength
     * @return std::string
     */
    std::string md5Crack(const std::string hash, const int threadCount, const int passwdLength);

    /**
     * @brief Test speed of cracking MD5 hash
     *
     * @param threadCount
     * @param passwdLength
     * @return int speed in hashes per second measured for 2 minutes
     */
    int md5SpeedTest(const int threadCount, const int passwdLength);

    bool verbose = false;

private:
    /**
     * @brief Get the passwd and increment it by passwdCount
     * @IMPORTANT: if returned empty vector, all passwords are checked
     * @return std::vector<char>
     */
    std::vector<char> getPasswd();

    /**
     * @brief thread which tries to crack the hash
     *
     */
    void thread(const int threadId);

    void progress();

    std::vector<std::thread> threads;
    std::atomic<bool> terminateThreads;
    std::vector<int> hashSpeed; // In hashes per second (each thread writes its speed using threadId as index)

    std::mutex getPasswdMutex;


    std::string hash; // hash to crack
    std::vector<char> passwd; // current password to check
    std::atomic<bool> lastPasswdReached; // if all passwords are checked
    const int passwdInThread = 1000000; // how many passwords to check by one thread at once
    std::string foundPasswd = "";
    std::vector<char> lastPasswd; // used by threads to check if reached last password

    //--------------- consts ---------------------------- 
    const char beginLetter = 97;
    const char endLetter = 122;
};
