#include <iostream>
#include <csignal>
#include <atomic>
#include <memory>
#include <thread>
#include <chrono>

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "DefenseEngine.h"

static std::atomic<bool> g_running(true);
static std::unique_ptr<mahoraga::DefenseEngine> g_engine;

static void SignalHandler(int signal)
{
    if (signal == SIGINT || signal == SIGTERM)
    {
        g_running = false;
        if (g_engine)
        {
            g_engine->Stop();
        }
    }
}

int main(int argc, char* argv[])
{
#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole != INVALID_HANDLE_VALUE)
    {
        DWORD dwMode = 0;
        if (GetConsoleMode(hConsole, &dwMode))
        {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hConsole, dwMode);
        }
    }
    SetConsoleOutputCP(CP_UTF8);
#endif

    std::signal(SIGINT, SignalHandler);
    std::signal(SIGTERM, SignalHandler);

    std::string config_path = "config/mahoraga.conf";

    if (argc > 1)
    {
        config_path = argv[1];
    }

    std::cout << "\033[1;36m";
    std::cout << "  __  __    _    _   _  ___  ____    _    ____  ___  \n";
    std::cout << " |  \\/  |  / \\  | | | |/ _ \\|  _ \\  / \\  |  _ \\|_ _| \n";
    std::cout << " | |\\/| | / _ \\ | |_| | | | | |_) |/ _ \\ | |_) || |  \n";
    std::cout << " | |  | |/ ___ \\|  _  | |_| |  _ </ ___ \\|  __/ | |  \n";
    std::cout << " |_|  |_/_/   \\_\\_| |_|\\___/|_| \\_\\_/   \\_\\_|  |___| \n";
    std::cout << "\033[0m";
    std::cout << "\033[1;32m";
    std::cout << "  Network Defense & Auditing System v1.0.0\n";
    std::cout << "\033[0m\n";

    try
    {
        g_engine = std::make_unique<mahoraga::DefenseEngine>();

        if (!g_engine->Initialize(config_path))
        {
            std::cerr << "\033[1;31m[FATAL] Engine initialization failed\033[0m\n";
            return 1;
        }

        if (!g_engine->Start())
        {
            std::cerr << "\033[1;31m[FATAL] Engine failed to start\033[0m\n";
            return 1;
        }

        while (g_running && g_engine->IsRunning())
        {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            g_engine->PrintStatus();
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "\033[1;31m[FATAL] " << ex.what() << "\033[0m\n";
        return 1;
    }
    catch (...)
    {
        std::cerr << "\033[1;31m[FATAL] Unknown exception\033[0m\n";
        return 1;
    }

    g_engine.reset();

    std::cout << "\033[1;32mMahoraga Defense Engine terminated cleanly\033[0m\n";
    return 0;
}

