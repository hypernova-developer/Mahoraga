#include "Logger.h"
#include <sstream>
#include <iomanip>
#include <iostream>

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace mahoraga
{

Logger::Logger(const LoggingConfig& config)
    : config_(config)
    , running_(true)
{
    if (config_.sdcard_enabled)
    {
        OpenSDCardFile();
    }

    worker_thread_ = std::thread(&Logger::WorkerLoop, this);
}

Logger::~Logger()
{
    running_ = false;
    cv_.notify_one();

    if (worker_thread_.joinable())
    {
        worker_thread_.join();
    }

    Flush();
    CloseSDCardFile();
}

void Logger::Log(LogLevel level, const std::string& message)
{
    LogEntry entry;
    entry.level = level;
    entry.message = message;
    entry.timestamp = std::chrono::system_clock::now();

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        log_queue_.push(entry);
    }

    cv_.notify_one();
}

void Logger::LogAlert(const std::string& alert_type, const std::string& details)
{
    std::string message = "[ALERT:" + alert_type + "] " + details;

    Log(LogLevel::Alert, message);
    std::cout << "\033[1;31m" << message << "\033[0m" << std::endl;
}

void Logger::Flush()
{
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);

        while (!log_queue_.empty())
        {
            LogEntry entry = log_queue_.front();
            log_queue_.pop();

            if (config_.serial_enabled)
            {
                WriteToSerial(entry);
            }

            if (config_.sdcard_enabled && sd_card_file_.is_open())
            {
                WriteToSDCard(entry);
            }

            if (config_.webui_enabled)
            {
                WriteToWebUI(entry);
            }
        }
    }

    if (sd_card_file_.is_open())
    {
        sd_card_file_.flush();
    }
}

void Logger::SetConfig(const LoggingConfig& config)
{
    std::lock_guard<std::mutex> lock(config_mutex_);

    if (config_.sdcard_enabled && !config.sdcard_enabled)
    {
        CloseSDCardFile();
    }
    else if (!config_.sdcard_enabled && config.sdcard_enabled)
    {
        config_ = config;
        OpenSDCardFile();
        return;
    }

    config_ = config;

    if (config_.sdcard_enabled && !sd_card_file_.is_open())
    {
        OpenSDCardFile();
    }
}

bool Logger::IsSerialEnabled() const
{
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_.serial_enabled;
}

bool Logger::IsWebUIEnabled() const
{
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_.webui_enabled;
}

bool Logger::IsSDCardEnabled() const
{
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_.sdcard_enabled;
}

void Logger::WorkerLoop()
{
    while (running_)
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);

        cv_.wait_for(lock, std::chrono::milliseconds(100),
            [this]() { return !log_queue_.empty() || !running_; });

        if (!running_ && log_queue_.empty())
        {
            break;
        }

        while (!log_queue_.empty())
        {
            LogEntry entry = log_queue_.front();
            log_queue_.pop();

            lock.unlock();

            {
                std::lock_guard<std::mutex> config_lock(config_mutex_);

                if (config_.serial_enabled)
                {
                    WriteToSerial(entry);
                }

                if (config_.sdcard_enabled && sd_card_file_.is_open())
                {
                    WriteToSDCard(entry);
                }

                if (config_.webui_enabled)
                {
                    WriteToWebUI(entry);
                }
            }

            std::cout << FormatLogEntry(entry) << std::endl;

            lock.lock();
        }
    }
}

void Logger::WriteToSerial(const LogEntry& entry)
{
    std::string formatted = FormatLogEntry(entry);

#ifdef _WIN32
    HANDLE hSerial = CreateFileA(
        config_.serial_port.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (hSerial != INVALID_HANDLE_VALUE)
    {
        DCB dcbSerialParams = {0};
        dcbSerialParams.DCBlength = sizeof(dcbSerialParams);

        if (GetCommState(hSerial, &dcbSerialParams))
        {
            dcbSerialParams.BaudRate = config_.serial_baud;
            dcbSerialParams.ByteSize = 8;
            dcbSerialParams.StopBits = ONESTOPBIT;
            dcbSerialParams.Parity = NOPARITY;
            SetCommState(hSerial, &dcbSerialParams);
        }

        DWORD bytes_written;
        WriteFile(hSerial, formatted.c_str(),
                  static_cast<DWORD>(formatted.size()), &bytes_written, nullptr);
        CloseHandle(hSerial);
    }
#else
    static_cast<void>(entry);
#endif
}

void Logger::WriteToSDCard(const LogEntry& entry)
{
    if (sd_card_file_.is_open())
    {
        sd_card_file_ << FormatLogEntry(entry) << std::endl;
    }
}

void Logger::WriteToWebUI(const LogEntry& entry)
{
    static_cast<void>(entry);
}

std::string Logger::LogLevelToString(LogLevel level)
{
    switch (level)
    {
        case LogLevel::Debug:
            return "DEBUG";
        case LogLevel::Info:
            return "INFO";
        case LogLevel::Warning:
            return "WARNING";
        case LogLevel::Alert:
            return "ALERT";
        case LogLevel::Critical:
            return "CRITICAL";
        default:
            return "UNKNOWN";
    }
}

std::string Logger::FormatTimestamp(const std::chrono::system_clock::time_point& ts)
{
    auto time_t = std::chrono::system_clock::to_time_t(ts);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        ts.time_since_epoch()
    ).count() % 1000;

    std::tm tm;
#ifdef _WIN32
    localtime_s(&tm, &time_t);
#else
    localtime_r(&time_t, &tm);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
        << "." << std::setw(3) << std::setfill('0') << ms;
    return oss.str();
}

std::string Logger::FormatLogEntry(const LogEntry& entry)
{
    std::ostringstream oss;
    oss << "[" << FormatTimestamp(entry.timestamp) << "]"
        << "[" << LogLevelToString(entry.level) << "] "
        << entry.message;
    return oss.str();
}

void Logger::OpenSDCardFile()
{
    std::string filepath = config_.sdcard_path + "/mahoraga_defense.log";
    sd_card_file_.open(filepath, std::ios::app);

    if (!sd_card_file_.is_open())
    {
        std::cerr << "Failed to open SD card log file: " << filepath << std::endl;
    }
}

void Logger::CloseSDCardFile()
{
    if (sd_card_file_.is_open())
    {
        sd_card_file_.close();
    }
}

}

