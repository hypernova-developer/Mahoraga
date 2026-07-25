#ifndef MAHORAGA_LOGGER_H
#define MAHORAGA_LOGGER_H

#include <string>
#include <fstream>
#include <mutex>
#include <atomic>
#include <queue>
#include <thread>
#include <condition_variable>
#include <chrono>
#include "ConfigurationManager.h"

namespace mahoraga
{

enum class LogLevel
{
    Debug    = 0,
    Info     = 1,
    Warning  = 2,
    Alert    = 3,
    Critical = 4
};

struct LogEntry
{
    LogLevel    level;
    std::string message;
    std::chrono::system_clock::time_point timestamp;
};

class Logger
{
public:
    Logger(const LoggingConfig& config);
    ~Logger();

    void Log(LogLevel level, const std::string& message);
    void LogAlert(const std::string& alert_type, const std::string& details);
    void Flush();
    void SetConfig(const LoggingConfig& config);

    bool IsSerialEnabled() const;
    bool IsWebUIEnabled() const;
    bool IsSDCardEnabled() const;

private:
    LoggingConfig                config_;
    mutable std::mutex           config_mutex_;
    std::ofstream                sd_card_file_;
    std::atomic<bool>            running_;
    std::thread                  worker_thread_;
    std::queue<LogEntry>         log_queue_;
    std::mutex                   queue_mutex_;
    std::condition_variable      cv_;

    void WorkerLoop();
    void WriteToSerial(const LogEntry& entry);
    void WriteToSDCard(const LogEntry& entry);
    void WriteToWebUI(const LogEntry& entry);
    std::string LogLevelToString(LogLevel level);
    std::string FormatTimestamp(const std::chrono::system_clock::time_point& ts);
    std::string FormatLogEntry(const LogEntry& entry);
    void OpenSDCardFile();
    void CloseSDCardFile();
};

}

#endif

