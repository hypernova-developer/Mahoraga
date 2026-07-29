#include "DefenseEngine.hpp"
#include <iostream>
#include <string>
#include <csignal>
#include <atomic>
#include <chrono>
#include <thread>

std::atomic<bool> g_running(true);

void handleSignal(int sig)
{
    g_running = false;
}

int main(int argc, char* argv[])
{
    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    bool spin = false;
    int interval = 5;
    std::string cgroupDir = "/sys/fs/cgroup";
    uint64_t memLimit = 524288000;
    int pidLimit = 100;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--spin")
        {
            spin = true;
        }
        else if (arg == "--interval" && i + 1 < argc)
        {
            interval = std::stoi(argv[++i]);
        }
        else if (arg == "--cgroup-dir" && i + 1 < argc)
        {
            cgroupDir = argv[++i];
        }
        else if (arg == "--mem-limit" && i + 1 < argc)
        {
            memLimit = std::stoull(argv[++i]);
        }
        else if (arg == "--pid-limit" && i + 1 < argc)
        {
            pidLimit = std::stoi(argv[++i]);
        }
    }

    try
    {
        mahoraga::DefenseEngine engine(cgroupDir, memLimit, pidLimit);
        if (spin)
        {
            while (g_running)
            {
                engine.scanAndDefend();
                std::this_thread::sleep_for(std::chrono::seconds(interval));
            }
        }
        else
        {
            engine.scanAndDefend();
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
