#include <iostream>
#include <csignal>
#include <atomic>
#include <memory>
#include <thread>
#include <chrono>
#include <string>
#include <vector>
#include <array>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cctype>
#include <iomanip>
#include <cstdint>
#include <optional>
#include <deque>
#include <map>
#include <unordered_map>

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <pcap.h>

namespace mahoraga
{

enum class FrameType : uint8_t
{
    Management     = 0x00,
    Control        = 0x01,
    Data           = 0x02
};

enum class ManagementSubtype : uint8_t
{
    AssociationRequest      = 0x00,
    AssociationResponse     = 0x01,
    ReassociationRequest    = 0x02,
    ReassociationResponse   = 0x03,
    ProbeRequest            = 0x04,
    ProbeResponse           = 0x05,
    Beacon                  = 0x08,
    ATIM                    = 0x09,
    Disassociation          = 0x0A,
    Authentication          = 0x0B,
    Deauthentication        = 0x0C,
    Action                  = 0x0D
};

enum class ControlSubtype : uint8_t
{
    Trigger       = 0x02,
    Beamforming   = 0x03,
    VHT_NDP_Ann   = 0x04,
    ControlFrame  = 0x07,
    BlockAckReq   = 0x08,
    BlockAck      = 0x09,
    PS_Poll       = 0x0A,
    RTS           = 0x0B,
    CTS           = 0x0C,
    ACK           = 0x0D,
    CF_End        = 0x0E,
    CF_End_ACK    = 0x0F
};

struct RadioTapHeader
{
    uint8_t  version;
    uint8_t  pad;
    uint16_t length;
    uint32_t present;
};

struct FrameControl
{
    uint8_t protocol_version : 2;
    uint8_t type             : 2;
    uint8_t subtype          : 4;
    uint8_t to_ds            : 1;
    uint8_t from_ds          : 1;
    uint8_t more_frag        : 1;
    uint8_t retry            : 1;
    uint8_t power_mgmt       : 1;
    uint8_t more_data        : 1;
    uint8_t protected_frame  : 1;
    uint8_t order            : 1;
};

struct ManagementFrameHeader
{
    FrameControl frame_control;
    uint16_t     duration;
    uint8_t      da[6];
    uint8_t      sa[6];
    uint8_t      bssid[6];
    uint16_t     seq_ctrl;
};

struct DeauthFrame
{
    ManagementFrameHeader header;
    uint16_t              reason_code;
};

struct BeaconFrame
{
    ManagementFrameHeader header;
    uint64_t              timestamp;
    uint16_t              beacon_interval;
    uint16_t              capability;
};

struct SSIDElement
{
    uint8_t element_id;
    uint8_t length;
    uint8_t ssid[32];
};

constexpr int MAC_ADDR_LEN      = 6;
constexpr int MAX_SSID_LEN      = 32;
constexpr int MAX_CHANNELS      = 64;
constexpr int MAX_WHITELIST     = 256;
constexpr int MAX_BLACKLIST     = 256;
constexpr int RING_BUFFER_SIZE  = 4096;
constexpr int MAX_DEAUTH_HISTORY = 1024;

struct LoggingConfig
{
    bool     serial_enabled;
    std::string serial_port;
    int      serial_baud;
    bool     webui_enabled;
    int      webui_port;
    bool     sdcard_enabled;
    std::string sdcard_path;
};

struct AlarmConfig
{
    bool     alarm_enabled;
    int      alarm_duration_ms;
    int      alarm_interval_ms;
};

struct LEDConfig
{
    bool     led_enabled;
    int      led_pin;
};

struct DisplayConfig
{
    bool     display_enabled;
};

class ConfigurationManager
{
public:
    ConfigurationManager();

    bool LoadFromFile(const std::string& filepath);

    const std::vector<int>& GetChannels2GHz() const;
    const std::vector<int>& GetChannels5GHz() const;

    const std::vector<std::array<uint8_t, 6>>& GetBSSIDWhitelist() const;
    const std::vector<std::array<uint8_t, 6>>& GetBSSIDBlacklist() const;
    const std::vector<std::string>& GetSSIDWhitelist() const;
    const std::vector<std::string>& GetSSIDBlacklist() const;

    int GetDeauthThreshold() const;
    int GetDeauthWindowSec() const;

    const LoggingConfig& GetLoggingConfig() const;
    const AlarmConfig& GetAlarmConfig() const;
    const LEDConfig& GetLEDConfig() const;
    const DisplayConfig& GetDisplayConfig() const;

    void SetChannels2GHz(const std::vector<int>& channels);
    void SetChannels5GHz(const std::vector<int>& channels);
    void SetDeauthThreshold(int threshold);
    void SetLoggingConfig(const LoggingConfig& cfg);
    void SetAlarmConfig(const AlarmConfig& cfg);
    void SetLEDConfig(const LEDConfig& cfg);
    void SetDisplayConfig(const DisplayConfig& cfg);

private:
    std::vector<int> channels_2ghz_;
    std::vector<int> channels_5ghz_;

    std::vector<std::array<uint8_t, 6>> bssid_whitelist_;
    std::vector<std::array<uint8_t, 6>> bssid_blacklist_;
    std::vector<std::string> ssid_whitelist_;
    std::vector<std::string> ssid_blacklist_;

    int  deauth_threshold_;
    int  deauth_window_sec_;

    LoggingConfig logging_;
    AlarmConfig   alarm_;
    LEDConfig     led_;
    DisplayConfig display_;

    static std::array<uint8_t, 6> ParseMAC(const std::string& mac_str);
};

ConfigurationManager::ConfigurationManager()
    : deauth_threshold_(10)
    , deauth_window_sec_(1)
{
    channels_2ghz_ = {1, 6, 11};
    channels_5ghz_ = {36, 40, 44, 48, 149, 153, 157, 161};

    logging_.serial_enabled   = true;
    logging_.serial_port      = "COM3";
    logging_.serial_baud      = 115200;
    logging_.webui_enabled    = true;
    logging_.webui_port       = 8080;
    logging_.sdcard_enabled   = true;
    logging_.sdcard_path      = "/mnt/sd";

    alarm_.alarm_enabled      = true;
    alarm_.alarm_duration_ms  = 5000;
    alarm_.alarm_interval_ms  = 1000;

    led_.led_enabled          = true;
    led_.led_pin              = 13;

    display_.display_enabled  = true;
}

std::array<uint8_t, 6> ConfigurationManager::ParseMAC(const std::string& mac_str)
{
    std::array<uint8_t, 6> mac{};
    std::string cleaned;
    for (char c : mac_str)
    {
        if (c != ':' && c != '-' && c != ' ')
        {
            cleaned += c;
        }
    }
    if (cleaned.length() < 12)
    {
        return mac;
    }
    for (int i = 0; i < 6; i++)
    {
        std::string byte_str = cleaned.substr(i * 2, 2);
        mac[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
    }
    return mac;
}

bool ConfigurationManager::LoadFromFile(const std::string& filepath)
{
    std::ifstream file(filepath);
    if (!file.is_open())
    {
        return false;
    }

    std::string line;
    std::string current_section;

    while (std::getline(file, line))
    {
        if (line.empty() || line[0] == '#' || line[0] == ';')
        {
            continue;
        }

        if (line[0] == '[')
        {
            size_t end = line.find(']');
            if (end != std::string::npos)
            {
                current_section = line.substr(1, end - 1);
            }
            continue;
        }

        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos)
        {
            continue;
        }

        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);

        key.erase(key.begin(), std::find_if(key.begin(), key.end(),
            [](unsigned char c) { return !std::isspace(c); }));
        key.erase(std::find_if(key.rbegin(), key.rend(),
            [](unsigned char c) { return !std::isspace(c); }).base(), key.end());

        value.erase(value.begin(), std::find_if(value.begin(), value.end(),
            [](unsigned char c) { return !std::isspace(c); }));
        value.erase(std::find_if(value.rbegin(), value.rend(),
            [](unsigned char c) { return !std::isspace(c); }).base(), value.end());

        if (current_section == "channels")
        {
            if (key == "channels_2ghz")
            {
                channels_2ghz_.clear();
                std::stringstream ss(value);
                std::string token;
                while (std::getline(ss, token, ','))
                {
                    token.erase(token.begin(), std::find_if(token.begin(), token.end(),
                        [](unsigned char c) { return !std::isspace(c); }));
                    if (!token.empty())
                    {
                        channels_2ghz_.push_back(std::stoi(token));
                    }
                }
            }
            else if (key == "channels_5ghz")
            {
                channels_5ghz_.clear();
                std::stringstream ss(value);
                std::string token;
                while (std::getline(ss, token, ','))
                {
                    token.erase(token.begin(), std::find_if(token.begin(), token.end(),
                        [](unsigned char c) { return !std::isspace(c); }));
                    if (!token.empty())
                    {
                        channels_5ghz_.push_back(std::stoi(token));
                    }
                }
            }
        }
        else if (current_section == "bssid_whitelist")
        {
            if (!value.empty())
            {
                bssid_whitelist_.push_back(ParseMAC(value));
            }
        }
        else if (current_section == "bssid_blacklist")
        {
            if (!value.empty())
            {
                bssid_blacklist_.push_back(ParseMAC(value));
            }
        }
        else if (current_section == "ssid_whitelist")
        {
            if (!value.empty())
            {
                ssid_whitelist_.push_back(value);
            }
        }
        else if (current_section == "ssid_blacklist")
        {
            if (!value.empty())
            {
                ssid_blacklist_.push_back(value);
            }
        }
        else if (current_section == "deauth_detection")
        {
            if (key == "deauth_threshold")
            {
                deauth_threshold_ = std::stoi(value);
            }
            else if (key == "deauth_window_sec")
            {
                deauth_window_sec_ = std::stoi(value);
            }
        }
        else if (current_section == "logging")
        {
            if (key == "serial_enabled")
            {
                logging_.serial_enabled = (value == "true" || value == "1");
            }
            else if (key == "serial_port")
            {
                logging_.serial_port = value;
            }
            else if (key == "serial_baud")
            {
                logging_.serial_baud = std::stoi(value);
            }
            else if (key == "webui_enabled")
            {
                logging_.webui_enabled = (value == "true" || value == "1");
            }
            else if (key == "webui_port")
            {
                logging_.webui_port = std::stoi(value);
            }
            else if (key == "sdcard_enabled")
            {
                logging_.sdcard_enabled = (value == "true" || value == "1");
            }
            else if (key == "sdcard_path")
            {
                logging_.sdcard_path = value;
            }
        }
        else if (current_section == "alarm")
        {
            if (key == "alarm_enabled")
            {
                alarm_.alarm_enabled = (value == "true" || value == "1");
            }
            else if (key == "alarm_duration_ms")
            {
                alarm_.alarm_duration_ms = std::stoi(value);
            }
            else if (key == "alarm_interval_ms")
            {
                alarm_.alarm_interval_ms = std::stoi(value);
            }
        }
        else if (current_section == "led")
        {
            if (key == "led_enabled")
            {
                led_.led_enabled = (value == "true" || value == "1");
            }
            else if (key == "led_pin")
            {
                led_.led_pin = std::stoi(value);
            }
        }
        else if (current_section == "display")
        {
            if (key == "display_enabled")
            {
                display_.display_enabled = (value == "true" || value == "1");
            }
        }
    }

    return true;
}

const std::vector<int>& ConfigurationManager::GetChannels2GHz() const
{
    return channels_2ghz_;
}

const std::vector<int>& ConfigurationManager::GetChannels5GHz() const
{
    return channels_5ghz_;
}

const std::vector<std::array<uint8_t, 6>>& ConfigurationManager::GetBSSIDWhitelist() const
{
    return bssid_whitelist_;
}

const std::vector<std::array<uint8_t, 6>>& ConfigurationManager::GetBSSIDBlacklist() const
{
    return bssid_blacklist_;
}

const std::vector<std::string>& ConfigurationManager::GetSSIDWhitelist() const
{
    return ssid_whitelist_;
}

const std::vector<std::string>& ConfigurationManager::GetSSIDBlacklist() const
{
    return ssid_blacklist_;
}

int ConfigurationManager::GetDeauthThreshold() const
{
    return deauth_threshold_;
}

int ConfigurationManager::GetDeauthWindowSec() const
{
    return deauth_window_sec_;
}

const LoggingConfig& ConfigurationManager::GetLoggingConfig() const
{
    return logging_;
}

const AlarmConfig& ConfigurationManager::GetAlarmConfig() const
{
    return alarm_;
}

const LEDConfig& ConfigurationManager::GetLEDConfig() const
{
    return led_;
}

const DisplayConfig& ConfigurationManager::GetDisplayConfig() const
{
    return display_;
}

void ConfigurationManager::SetChannels2GHz(const std::vector<int>& channels)
{
    channels_2ghz_ = channels;
}

void ConfigurationManager::SetChannels5GHz(const std::vector<int>& channels)
{
    channels_5ghz_ = channels;
}

void ConfigurationManager::SetDeauthThreshold(int threshold)
{
    deauth_threshold_ = threshold;
}

void ConfigurationManager::SetLoggingConfig(const LoggingConfig& cfg)
{
    logging_ = cfg;
}

void ConfigurationManager::SetAlarmConfig(const AlarmConfig& cfg)
{
    alarm_ = cfg;
}

void ConfigurationManager::SetLEDConfig(const LEDConfig& cfg)
{
    led_ = cfg;
}

void ConfigurationManager::SetDisplayConfig(const DisplayConfig& cfg)
{
    display_ = cfg;
}

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

struct ParsedFrame
{
    FrameType                    frame_type;
    uint8_t                      subtype;
    std::array<uint8_t, 6>      transmitter_addr;
    std::array<uint8_t, 6>      receiver_addr;
    std::array<uint8_t, 6>      bssid;
    std::string                  ssid;
    int                          channel;
    int                          signal_dbm;
    uint16_t                     reason_code;
    uint64_t                     timestamp_us;
    bool                         is_deauth;
    bool                         is_disassociation;
    bool                         is_beacon;
};

class FrameParser
{
public:
    FrameParser();

    std::optional<ParsedFrame> Parse(const uint8_t* data, int length) const;

    static std::string MacToString(const std::array<uint8_t, 6>& mac);
    static bool MacsEqual(const std::array<uint8_t, 6>& a, const std::array<uint8_t, 6>& b);

private:
    static FrameType GetFrameType(const FrameControl& fc) ;
    static uint8_t GetSubtype(const FrameControl& fc) ;
    static int ParseRadioTapHeader(const uint8_t* data, int length, int& signal_dbm) ;
    static std::string ParseSSIDFromBeacon(const uint8_t* body, int body_length) ;
    static uint16_t ParseReasonCode(const uint8_t* body, int body_length) ;
};

FrameParser::FrameParser()
{
}

std::optional<ParsedFrame> FrameParser::Parse(const uint8_t* data, int length) const
{
    if (!data || length < static_cast<int>(sizeof(RadioTapHeader) + sizeof(FrameControl)))
    {
        return std::nullopt;
    }

    ParsedFrame frame{};
    frame.channel = 0;
    frame.signal_dbm = 0;
    frame.reason_code = 0;
    frame.timestamp_us = 0;
    frame.is_deauth = false;
    frame.is_disassociation = false;
    frame.is_beacon = false;

    std::memset(frame.transmitter_addr.data(), 0, 6);
    std::memset(frame.receiver_addr.data(), 0, 6);
    std::memset(frame.bssid.data(), 0, 6);

    int offset = ParseRadioTapHeader(data, length, frame.signal_dbm);
    if (offset < 0 || offset >= length)
    {
        return std::nullopt;
    }

    if (static_cast<size_t>(length - offset) < sizeof(FrameControl))
    {
        return std::nullopt;
    }

    FrameControl fc;
    std::memcpy(&fc, data + offset, sizeof(FrameControl));

    frame.frame_type = GetFrameType(fc);
    frame.subtype = GetSubtype(fc);

    uint8_t frame_subtype = fc.subtype;
    uint8_t frame_type_bits = fc.type;

    offset += sizeof(FrameControl);

    if (frame_type_bits == 0x00)
    {
        if (offset + static_cast<int>(sizeof(ManagementFrameHeader) - sizeof(FrameControl)) > length)
        {
            return std::nullopt;
        }

        ManagementFrameHeader mgmt_hdr;
        std::memcpy(&mgmt_hdr, data + offset - sizeof(FrameControl), sizeof(ManagementFrameHeader));

        std::memcpy(frame.transmitter_addr.data(), mgmt_hdr.sa, 6);
        std::memcpy(frame.receiver_addr.data(), mgmt_hdr.da, 6);
        std::memcpy(frame.bssid.data(), mgmt_hdr.bssid, 6);

        int header_size = sizeof(ManagementFrameHeader) - sizeof(FrameControl);
        offset += header_size;

        int body_length = length - offset;

        if (frame_subtype == 0x08 || frame_subtype == 0x05)
        {
            frame.is_beacon = true;
            if (offset + 12 <= length)
            {
                frame.ssid = ParseSSIDFromBeacon(data + offset, body_length);
            }
        }
        else if (frame_subtype == 0x0C)
        {
            frame.is_deauth = true;
            if (body_length >= 2)
            {
                frame.reason_code = ParseReasonCode(data + offset, body_length);
            }
        }
        else if (frame_subtype == 0x0A)
        {
            frame.is_disassociation = true;
            if (body_length >= 2)
            {
                frame.reason_code = ParseReasonCode(data + offset, body_length);
            }
        }
    }
    else if (frame_type_bits == 0x01)
    {
        if (offset + 10 <= length)
        {
            uint16_t fc_duration;
            std::memcpy(&fc_duration, data + offset - sizeof(FrameControl) + 2, 2);

            uint8_t addr1[6];
            uint8_t addr2[6];
            std::memcpy(addr1, data + offset - sizeof(FrameControl) + 4, 6);

            if (offset - sizeof(FrameControl) + 10 + 6 <= length)
            {
                std::memcpy(addr2, data + offset - sizeof(FrameControl) + 10, 6);
                std::memcpy(frame.transmitter_addr.data(), addr2, 6);
            }
            std::memcpy(frame.receiver_addr.data(), addr1, 6);
            std::memcpy(frame.bssid.data(), addr1, 6);
        }
    }
    else if (frame_type_bits == 0x02)
    {
        if (offset + 10 <= length)
        {
            uint8_t addr1[6];
            uint8_t addr2[6];
            std::memcpy(addr1, data + offset - sizeof(FrameControl) + 4, 6);

            if (offset - sizeof(FrameControl) + 10 + 6 <= length)
            {
                std::memcpy(addr2, data + offset - sizeof(FrameControl) + 10, 6);
                std::memcpy(frame.transmitter_addr.data(), addr2, 6);
            }
            std::memcpy(frame.receiver_addr.data(), addr1, 6);
            std::memcpy(frame.bssid.data(), addr1, 6);
        }
    }

    return frame;
}

std::string FrameParser::MacToString(const std::array<uint8_t, 6>& mac)
{
    std::ostringstream oss;
    for (int i = 0; i < 6; i++)
    {
        if (i > 0)
        {
            oss << ":";
        }
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(mac[i]);
    }
    return oss.str();
}

bool FrameParser::MacsEqual(const std::array<uint8_t, 6>& a, const std::array<uint8_t, 6>& b)
{
    return std::memcmp(a.data(), b.data(), 6) == 0;
}

FrameType FrameParser::GetFrameType(const FrameControl& fc)
{
    switch (fc.type)
    {
        case 0x00:
            return FrameType::Management;
        case 0x01:
            return FrameType::Control;
        case 0x02:
            return FrameType::Data;
        default:
            return FrameType::Management;
    }
}

uint8_t FrameParser::GetSubtype(const FrameControl& fc)
{
    return fc.subtype;
}

int FrameParser::ParseRadioTapHeader(const uint8_t* data, int length, int& signal_dbm)
{
    if (length < static_cast<int>(sizeof(RadioTapHeader)))
    {
        return -1;
    }

    RadioTapHeader radiotap;
    std::memcpy(&radiotap, data, sizeof(RadioTapHeader));

    if (radiotap.length < sizeof(RadioTapHeader) || radiotap.length > static_cast<uint16_t>(length))
    {
        return -1;
    }

    signal_dbm = 0;

    uint32_t present = radiotap.present;
    int offset = sizeof(RadioTapHeader);

    if (present & (1 << 0))
    {
        if (offset + 8 <= radiotap.length)
        {
            offset += 8;
        }
    }

    if (present & (1 << 1))
    {
        if (offset + 1 <= radiotap.length)
        {
            offset += 1;
        }
    }

    if (present & (1 << 2))
    {
        if (offset + 1 <= radiotap.length)
        {
            signal_dbm = static_cast<int>(*reinterpret_cast<const int8_t*>(data + offset));
            offset += 1;
        }
    }

    if (present & (1 << 3))
    {
        if (offset + 1 <= radiotap.length)
        {
            offset += 1;
        }
    }

    if (present & (1 << 4))
    {
        if (offset + 1 <= radiotap.length)
        {
            offset += 1;
        }
    }

    if (present & (1 << 5))
    {
        if (offset + 1 <= radiotap.length)
        {
            offset += 1;
        }
    }

    if (present & (1 << 6))
    {
        if (offset + 4 <= radiotap.length)
        {
            offset += 4;
        }
    }

    return radiotap.length;
}

std::string FrameParser::ParseSSIDFromBeacon(const uint8_t* body, int body_length)
{
    int offset = 12;

    while (offset + 2 <= body_length)
    {
        uint8_t element_id = body[offset];
        uint8_t element_len = body[offset + 1];

        if (element_id == 0x00)
        {
            if (element_len > 0 && offset + 2 + element_len <= static_cast<size_t>(body_length))
            {
                return std::string(
                    reinterpret_cast<const char*>(body + offset + 2),
                    std::min(static_cast<int>(element_len), 32)
                );
            }
            break;
        }

        offset += 2 + element_len;
    }

    return "";
}

uint16_t FrameParser::ParseReasonCode(const uint8_t* body, int body_length)
{
    if (body_length < 2)
    {
        return 0;
    }

    uint16_t reason;
    std::memcpy(&reason, body, sizeof(uint16_t));
    return reason;
}

enum class AlertLevel
{
    None     = 0,
    Info     = 1,
    Low      = 2,
    Medium   = 3,
    High     = 4,
    Critical = 5
};

struct RogueAPResult
{
    std::array<uint8_t, 6>         bssid;
    std::string                    ssid;
    int                            channel;
    int                            signal_dbm;
    bool                           is_rogue;
    AlertLevel                     alert_level;
    std::string                    details;
    std::chrono::steady_clock::time_point first_seen;
};

class RogueAPDetector
{
public:
    RogueAPDetector(
        const std::vector<std::array<uint8_t, 6>>& bssid_whitelist,
        const std::vector<std::array<uint8_t, 6>>& bssid_blacklist,
        const std::vector<std::string>& ssid_whitelist,
        const std::vector<std::string>& ssid_blacklist
    ) ;

    void UpdateWhitelists(
        const std::vector<std::array<uint8_t, 6>>& bssid_whitelist,
        const std::vector<std::array<uint8_t, 6>>& bssid_blacklist,
        const std::vector<std::string>& ssid_whitelist,
        const std::vector<std::string>& ssid_blacklist
    ) ;

    RogueAPResult AnalyzeBeacon(const ParsedFrame& frame) ;
    std::vector<RogueAPResult> GetDetectedRogueAPs() const;
    void ClearKnownAPs() ;

private:
    mutable std::mutex mutex_;

    std::vector<std::array<uint8_t, 6>> bssid_whitelist_;
    std::vector<std::array<uint8_t, 6>> bssid_blacklist_;
    std::vector<std::string> ssid_whitelist_;
    std::vector<std::string> ssid_blacklist_;

    std::unordered_multimap<std::string, RogueAPResult> known_aps_;

    bool IsInBlacklist(const std::array<uint8_t, 6>& bssid, const std::string& ssid) ;
    bool IsInWhitelist(const std::array<uint8_t, 6>& bssid, const std::string& ssid) ;
    bool IsWhitelistActive() ;
    bool HasSpoofedBSSID(const std::array<uint8_t, 6>& bssid, const std::string& ssid) ;
    bool IsEvilTwin(const std::string& ssid) ;
    void UpdateAPTracker(const RogueAPResult& ap_info) ;
};

RogueAPDetector::RogueAPDetector(
    const std::vector<std::array<uint8_t, 6>>& bssid_whitelist,
    const std::vector<std::array<uint8_t, 6>>& bssid_blacklist,
    const std::vector<std::string>& ssid_whitelist,
    const std::vector<std::string>& ssid_blacklist
)
    : bssid_whitelist_(bssid_whitelist)
    , bssid_blacklist_(bssid_blacklist)
    , ssid_whitelist_(ssid_whitelist)
    , ssid_blacklist_(ssid_blacklist)
{
}

void RogueAPDetector::UpdateWhitelists(
    const std::vector<std::array<uint8_t, 6>>& bssid_whitelist,
    const std::vector<std::array<uint8_t, 6>>& bssid_blacklist,
    const std::vector<std::string>& ssid_whitelist,
    const std::vector<std::string>& ssid_blacklist
)
{
    std::lock_guard<std::mutex> lock(mutex_);
    bssid_whitelist_ = bssid_whitelist;
    bssid_blacklist_ = bssid_blacklist;
    ssid_whitelist_ = ssid_whitelist;
    ssid_blacklist_ = ssid_blacklist;
}

RogueAPResult RogueAPDetector::AnalyzeBeacon(const ParsedFrame& frame)
{
    RogueAPResult result;
    result.is_rogue = false;
    result.alert_level = AlertLevel::None;
    result.details = "";

    if (!frame.is_beacon)
    {
        return result;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    result.bssid = frame.bssid;
    result.ssid = frame.ssid;
    result.channel = frame.channel;
    result.signal_dbm = frame.signal_dbm;
    result.first_seen = std::chrono::steady_clock::now();

    UpdateAPTracker(result);

    if (IsInBlacklist(result.bssid, result.ssid))
    {
        result.is_rogue = true;
        result.alert_level = AlertLevel::High;
        result.details = "BSSID/SSID in blacklist - known unauthorized AP";
        return result;
    }

    if (IsWhitelistActive())
    {
        if (!IsInWhitelist(result.bssid, result.ssid))
        {
            result.is_rogue = true;
            result.alert_level = AlertLevel::Medium;
            result.details = "AP not in whitelist - unauthorized access point";
            return result;
        }
    }

    if (HasSpoofedBSSID(result.bssid, result.ssid))
    {
        result.is_rogue = true;
        result.alert_level = AlertLevel::Critical;
        result.details = "BSSID spoofing detected - cloned legitimate AP";
        return result;
    }

    if (IsEvilTwin(result.ssid))
    {
        result.is_rogue = true;
        result.alert_level = AlertLevel::Critical;
        result.details = "Evil Twin AP detected - multiple APs with same SSID";
        return result;
    }

    result.alert_level = AlertLevel::Info;
    result.details = "Authorized AP detected - no threat";

    return result;
}

bool RogueAPDetector::IsInBlacklist(const std::array<uint8_t, 6>& bssid, const std::string& ssid)
{
    for (const auto& blocked_bssid : bssid_blacklist_)
    {
        if (FrameParser::MacsEqual(bssid, blocked_bssid))
        {
            return true;
        }
    }

    for (const auto& blocked_ssid : ssid_blacklist_)
    {
        if (ssid == blocked_ssid)
        {
            return true;
        }
    }

    return false;
}

bool RogueAPDetector::IsInWhitelist(const std::array<uint8_t, 6>& bssid, const std::string& ssid)
{
    for (const auto& allowed_bssid : bssid_whitelist_)
    {
        if (FrameParser::MacsEqual(bssid, allowed_bssid))
        {
            return true;
        }
    }

    for (const auto& allowed_ssid : ssid_whitelist_)
    {
        if (!ssid.empty() && ssid == allowed_ssid)
        {
            return true;
        }
    }

    return false;
}

bool RogueAPDetector::IsWhitelistActive()
{
    return !bssid_whitelist_.empty() || !ssid_whitelist_.empty();
}

bool RogueAPDetector::HasSpoofedBSSID(const std::array<uint8_t, 6>& bssid, const std::string& ssid)
{
    auto range = known_aps_.equal_range(ssid);
    for (auto it = range.first; it != range.second; ++it)
    {
        if (FrameParser::MacsEqual(it->second.bssid, bssid))
        {
            continue;
        }
        if (it->second.ssid == ssid)
        {
            return true;
        }
    }

    return false;
}

bool RogueAPDetector::IsEvilTwin(const std::string& ssid)
{
    if (ssid.empty())
    {
        return false;
    }

    auto range = known_aps_.equal_range(ssid);
    int count = 0;
    for (auto it = range.first; it != range.second; ++it)
    {
        count++;
    }

    return count > 3;
}

void RogueAPDetector::UpdateAPTracker(const RogueAPResult& ap_info)
{
    if (ap_info.ssid.empty())
    {
        return;
    }

    known_aps_.insert({ap_info.ssid, ap_info});
}

std::vector<RogueAPResult> RogueAPDetector::GetDetectedRogueAPs() const
{
    std::vector<RogueAPResult> rogues;
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& pair : known_aps_)
    {
        if (pair.second.is_rogue)
        {
            rogues.push_back(pair.second);
        }
    }

    return rogues;
}

void RogueAPDetector::ClearKnownAPs()
{
    std::lock_guard<std::mutex> lock(mutex_);
    known_aps_.clear();
}

struct DeauthAlert
{
    std::array<uint8_t, 6>      source_mac;
    std::array<uint8_t, 6>      target_mac;
    std::array<uint8_t, 6>      bssid;
    uint16_t                     reason_code;
    int                          packet_rate;
    uint64_t                     timestamp_ms;
    bool                         is_flood;
};

class DeauthDetector
{
public:
    DeauthDetector(int threshold, int window_sec);

    void SetThreshold(int threshold, int window_sec);
    DeauthAlert AnalyzeFrame(const ParsedFrame& frame);
    DeauthAlert GetCurrentAlert() const;
    int GetCurrentRate() const;
    void Reset();

    static std::string ReasonCodeToString(uint16_t reason_code);
    static bool IsDeauthReasonSuspicious(uint16_t reason_code);

private:
    std::atomic<int>  threshold_;
    std::atomic<int>  window_sec_;

    mutable std::mutex                       mutex_;
    std::deque<std::chrono::steady_clock::time_point> deauth_timestamps_;
    std::vector<DeauthAlert>                 alerts_;
    DeauthAlert                              current_alert_;

    struct DeauthRecord
    {
        std::chrono::steady_clock::time_point timestamp;
        std::array<uint8_t, 6> source_mac;
        std::array<uint8_t, 6> target_mac;
        uint16_t reason_code;
    };

    std::deque<DeauthRecord> deauth_history_;

    void PruneOldRecords();
    int CalculateRate() const;
    bool IsFloodAttack();
};

DeauthDetector::DeauthDetector(int threshold, int window_sec)
    : threshold_(threshold)
    , window_sec_(window_sec)
{
    current_alert_.is_flood = false;
    current_alert_.packet_rate = 0;
    current_alert_.timestamp_ms = 0;
    current_alert_.reason_code = 0;
    std::memset(current_alert_.source_mac.data(), 0, 6);
    std::memset(current_alert_.target_mac.data(), 0, 6);
    std::memset(current_alert_.bssid.data(), 0, 6);
}

void DeauthDetector::SetThreshold(int threshold, int window_sec)
{
    threshold_.store(threshold);
    window_sec_.store(window_sec);
}

DeauthAlert DeauthDetector::AnalyzeFrame(const ParsedFrame& frame)
{
    DeauthAlert alert;
    alert.is_flood = false;
    alert.packet_rate = 0;
    alert.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    alert.reason_code = frame.reason_code;
    alert.source_mac = frame.transmitter_addr;
    alert.target_mac = frame.receiver_addr;
    alert.bssid = frame.bssid;

    if (!frame.is_deauth && !frame.is_disassociation)
    {
        return alert;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);

        DeauthRecord record;
        record.timestamp = std::chrono::steady_clock::now();
        record.source_mac = frame.transmitter_addr;
        record.target_mac = frame.receiver_addr;
        record.reason_code = frame.reason_code;

        deauth_history_.push_back(record);

        if (deauth_history_.size() > MAX_DEAUTH_HISTORY)
        {
            deauth_history_.pop_front();
        }

        PruneOldRecords();
        alert.packet_rate = CalculateRate();

        if (IsFloodAttack())
        {
            alert.is_flood = true;
            current_alert_ = alert;
            alerts_.push_back(alert);
        }
    }

    return alert;
}

DeauthAlert DeauthDetector::GetCurrentAlert() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return current_alert_;
}

int DeauthDetector::GetCurrentRate() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return CalculateRate();
}

void DeauthDetector::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    deauth_history_.clear();
    alerts_.clear();
    current_alert_.is_flood = false;
    current_alert_.packet_rate = 0;
}

void DeauthDetector::PruneOldRecords()
{
    auto now = std::chrono::steady_clock::now();
    auto window_start = now - std::chrono::seconds(window_sec_.load());

    while (!deauth_history_.empty() && deauth_history_.front().timestamp < window_start)
    {
        deauth_history_.pop_front();
    }
}

int DeauthDetector::CalculateRate() const
{
    return static_cast<int>(deauth_history_.size());
}

bool DeauthDetector::IsFloodAttack()
{
    int current_rate = CalculateRate();
    return current_rate >= threshold_.load();
}

std::string DeauthDetector::ReasonCodeToString(uint16_t reason_code)
{
    switch (reason_code)
    {
        case 0:
            return "Reserved";
        case 1:
            return "Unspecified reason";
        case 2:
            return "Previous authentication no longer valid";
        case 3:
            return "Deauthenticated because sending station is leaving (or has left) IBSS or ESS";
        case 4:
            return "Disassociated due to inactivity";
        case 5:
            return "Disassociated because AP is unable to handle all currently associated stations";
        case 6:
            return "Class 2 frame received from nonauthenticated station";
        case 7:
            return "Class 3 frame received from nonassociated station";
        case 8:
            return "Disassociated because sending station is leaving (or has left) BSS";
        case 9:
            return "Station requesting (re)association is not authenticated with responding station";
        default:
        {
            std::ostringstream oss;
            oss << "Unknown reason code: " << reason_code;
            return oss.str();
        }
    }
}

bool DeauthDetector::IsDeauthReasonSuspicious(uint16_t reason_code)
{
    switch (reason_code)
    {
        case 0:
        case 4:
        case 5:
        case 7:
        case 8:
            return false;
        default:
            return true;
    }
}

enum class AnomalyType
{
    None              = 0,
    HighPacketRate    = 1,
    BeaconFlood       = 2,
    ProbeRequestFlood = 3,
    NullDataFlood     = 4,
    ChannelHopping    = 5,
    UnusualFrameSize  = 6
};

struct TrafficAlert
{
    AnomalyType                    anomaly;
    AlertLevel                     severity;
    std::array<uint8_t, 6>        source_mac;
    std::string                    description;
    int                            rate;
    uint64_t                       timestamp_ms;
};

class TrafficAnalyzer
{
public:
    TrafficAnalyzer();

    TrafficAlert AnalyzeFrame(const ParsedFrame& frame);
    TrafficAlert GetCurrentAlert() const;
    void Reset();

    int GetTotalFrameCount() const;
    int GetManagementFrameCount() const;
    int GetControlFrameCount() const;
    int GetDataFrameCount() const;
    int GetPacketsPerSecond() const;

private:
    struct FlowStats
    {
        int packet_count;
        std::chrono::steady_clock::time_point last_seen;
    };

    std::atomic<int> total_frames_;
    std::atomic<int> mgmt_frames_;
    std::atomic<int> ctrl_frames_;
    std::atomic<int> data_frames_;

    mutable std::mutex mutex_;
    std::deque<std::chrono::steady_clock::time_point> frame_timestamps_;
    std::map<std::array<uint8_t, 6>, FlowStats> source_flows_;
    TrafficAlert current_alert_;

    static constexpr int RATE_WINDOW_SEC = 2;
    static constexpr int HIGH_RATE_THRESHOLD = 500;
    static constexpr int BEACON_FLOOD_THRESHOLD = 50;

    void PruneTimestamps();
    int CalculatePacketsPerSecond() const;
    bool CheckHighRateAnomaly();
    bool CheckBeaconFlood(int beacon_count);
    void UpdateFlowStats(const ParsedFrame& frame);
};

TrafficAnalyzer::TrafficAnalyzer()
    : total_frames_(0)
    , mgmt_frames_(0)
    , ctrl_frames_(0)
    , data_frames_(0)
{
    current_alert_.anomaly = AnomalyType::None;
    current_alert_.severity = AlertLevel::None;
    current_alert_.rate = 0;
    current_alert_.timestamp_ms = 0;
    std::memset(current_alert_.source_mac.data(), 0, 6);
}

TrafficAlert TrafficAnalyzer::AnalyzeFrame(const ParsedFrame& frame)
{
    total_frames_++;

    switch (frame.frame_type)
    {
        case FrameType::Management:
            mgmt_frames_++;
            break;
        case FrameType::Control:
            ctrl_frames_++;
            break;
        case FrameType::Data:
            data_frames_++;
            break;
    }

    TrafficAlert alert;
    alert.anomaly = AnomalyType::None;
    alert.severity = AlertLevel::None;
    alert.rate = 0;
    alert.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    alert.source_mac = frame.transmitter_addr;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        frame_timestamps_.push_back(std::chrono::steady_clock::now());
        PruneTimestamps();

        int pps = CalculatePacketsPerSecond();
        alert.rate = pps;

        if (CheckHighRateAnomaly())
        {
            alert.anomaly = AnomalyType::HighPacketRate;
            alert.severity = AlertLevel::High;
            alert.description = "Abnormally high packet rate detected: "
                                + std::to_string(pps) + " pps";
            current_alert_ = alert;
            return alert;
        }

        static int beacon_count = 0;
        if (frame.is_beacon)
        {
            beacon_count++;
            if (CheckBeaconFlood(beacon_count))
            {
                alert.anomaly = AnomalyType::BeaconFlood;
                alert.severity = AlertLevel::Medium;
                alert.description = "Beacon flood detected - possible beacon spoofing attack";
                current_alert_ = alert;
                beacon_count = 0;
                return alert;
            }
        }

        UpdateFlowStats(frame);
    }

    return alert;
}

TrafficAlert TrafficAnalyzer::GetCurrentAlert() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return current_alert_;
}

void TrafficAnalyzer::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    total_frames_ = 0;
    mgmt_frames_ = 0;
    ctrl_frames_ = 0;
    data_frames_ = 0;
    frame_timestamps_.clear();
    source_flows_.clear();
    current_alert_.anomaly = AnomalyType::None;
    current_alert_.severity = AlertLevel::None;
    current_alert_.rate = 0;
}

int TrafficAnalyzer::GetTotalFrameCount() const
{
    return total_frames_.load();
}

int TrafficAnalyzer::GetManagementFrameCount() const
{
    return mgmt_frames_.load();
}

int TrafficAnalyzer::GetControlFrameCount() const
{
    return ctrl_frames_.load();
}

int TrafficAnalyzer::GetDataFrameCount() const
{
    return data_frames_.load();
}

int TrafficAnalyzer::GetPacketsPerSecond() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return CalculatePacketsPerSecond();
}

void TrafficAnalyzer::PruneTimestamps()
{
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(RATE_WINDOW_SEC);

    while (!frame_timestamps_.empty() && frame_timestamps_.front() < cutoff)
    {
        frame_timestamps_.pop_front();
    }
}

int TrafficAnalyzer::CalculatePacketsPerSecond() const
{
    if (frame_timestamps_.empty())
    {
        return 0;
    }

    return static_cast<int>(frame_timestamps_.size()) / RATE_WINDOW_SEC;
}

bool TrafficAnalyzer::CheckHighRateAnomaly()
{
    return CalculatePacketsPerSecond() > HIGH_RATE_THRESHOLD;
}

bool TrafficAnalyzer::CheckBeaconFlood(int beacon_count)
{
    return beacon_count > BEACON_FLOOD_THRESHOLD;
}

void TrafficAnalyzer::UpdateFlowStats(const ParsedFrame& frame)
{
    std::array<uint8_t, 6> mac = frame.transmitter_addr;
    auto it = source_flows_.find(mac);

    if (it != source_flows_.end())
    {
        it->second.packet_count++;
        it->second.last_seen = std::chrono::steady_clock::now();
    }
    else
    {
        FlowStats stats;
        stats.packet_count = 1;
        stats.last_seen = std::chrono::steady_clock::now();
        source_flows_.insert({mac, stats});
    }
}

class AlarmManager
{
public:
    AlarmManager(
        bool alarm_enabled,
        int alarm_duration_ms,
        int alarm_interval_ms,
        bool led_enabled,
        int led_pin,
        bool display_enabled
    );

    ~AlarmManager();

    void TriggerAlert(AlertLevel level, const std::string& message);
    void ClearAlert();
    bool IsAlertActive() const;
    AlertLevel GetCurrentAlertLevel() const;
    std::string GetCurrentAlertMessage() const;

    void SetAlarmEnabled(bool enabled);
    void SetLEDEnabled(bool enabled);
    void SetDisplayEnabled(bool enabled);
    void SetAlarmDuration(int duration_ms);
    void SetAlarmInterval(int interval_ms);

private:
    std::atomic<bool>  alarm_enabled_;
    std::atomic<int>   alarm_duration_ms_;
    std::atomic<int>   alarm_interval_ms_;
    std::atomic<bool>  led_enabled_;
    int                led_pin_;
    std::atomic<bool>  display_enabled_;

    std::atomic<bool>              alert_active_;
    std::atomic<AlertLevel>        current_level_;
    mutable std::mutex             message_mutex_;
    std::string                    current_message_;
    std::thread                    alert_thread_;
    std::atomic<bool>              thread_running_;

    void AlertWorker();
    void ActivateSiren();
    void ActivateLED();
    void UpdateDisplay();
    void SendNotification(const std::string& message);

    std::condition_variable cv_;
    std::mutex cv_mutex_;
    void StopWorker();
};

AlarmManager::AlarmManager(
    bool alarm_enabled,
    int alarm_duration_ms,
    int alarm_interval_ms,
    bool led_enabled,
    int led_pin,
    bool display_enabled
)
    : alarm_enabled_(alarm_enabled)
    , alarm_duration_ms_(alarm_duration_ms)
    , alarm_interval_ms_(alarm_interval_ms)
    , led_enabled_(led_enabled)
    , led_pin_(led_pin)
    , display_enabled_(display_enabled)
    , alert_active_(false)
    , current_level_(AlertLevel::None)
    , thread_running_(false)
{
}

AlarmManager::~AlarmManager()
{
    StopWorker();
}

void AlarmManager::TriggerAlert(AlertLevel level, const std::string& message)
{
    if (level == AlertLevel::None)
    {
        return;
    }

    StopWorker();

    {
        std::lock_guard<std::mutex> lock(message_mutex_);
        current_message_ = message;
    }

    current_level_ = level;
    alert_active_ = true;
    thread_running_ = true;

    alert_thread_ = std::thread(&AlarmManager::AlertWorker, this);
}

void AlarmManager::ClearAlert()
{
    alert_active_ = false;
    {
        std::lock_guard<std::mutex> lock(message_mutex_);
        current_message_.clear();
    }
    current_level_ = AlertLevel::None;

    std::unique_lock<std::mutex> lock(cv_mutex_);
    cv_.notify_all();
}

void AlarmManager::StopWorker()
{
    thread_running_ = false;
    alert_active_ = false;

    {
        std::unique_lock<std::mutex> lock(cv_mutex_);
        cv_.notify_all();
    }

    if (alert_thread_.joinable())
    {
        alert_thread_.join();
    }
}

bool AlarmManager::IsAlertActive() const
{
    return alert_active_.load();
}

AlertLevel AlarmManager::GetCurrentAlertLevel() const
{
    return current_level_.load();
}

std::string AlarmManager::GetCurrentAlertMessage() const
{
    std::lock_guard<std::mutex> lock(message_mutex_);
    return current_message_;
}

void AlarmManager::SetAlarmEnabled(bool enabled)
{
    alarm_enabled_ = enabled;
}

void AlarmManager::SetLEDEnabled(bool enabled)
{
    led_enabled_ = enabled;
}

void AlarmManager::SetDisplayEnabled(bool enabled)
{
    display_enabled_ = enabled;
}

void AlarmManager::SetAlarmDuration(int duration_ms)
{
    alarm_duration_ms_ = duration_ms;
}

void AlarmManager::SetAlarmInterval(int interval_ms)
{
    alarm_interval_ms_ = interval_ms;
}

void AlarmManager::AlertWorker()
{
    while (thread_running_ && alert_active_)
    {
        if (alarm_enabled_)
        {
            ActivateSiren();
        }

        if (led_enabled_)
        {
            ActivateLED();
        }

        if (display_enabled_)
        {
            UpdateDisplay();
        }

        std::unique_lock<std::mutex> lock(cv_mutex_);

        cv_.wait_for(lock, std::chrono::milliseconds(alarm_interval_ms_.load()), [this]() {
            return !thread_running_ || !alert_active_;
        });
    }

    thread_running_ = false;
}

void AlarmManager::ActivateSiren()
{
    std::cout << "\a";
    std::cout.flush();
}

void AlarmManager::ActivateLED()
{
    std::cout << "\033[5m";
    std::cout << "[LED] ALERT ACTIVE";
    std::cout << "\033[25m";
    std::cout.flush();
}

void AlarmManager::UpdateDisplay()
{
    std::string level_str;
    AlertLevel level = current_level_.load();

    switch (level)
    {
        case AlertLevel::Low:
            level_str = "LOW";
            break;
        case AlertLevel::Medium:
            level_str = "MEDIUM";
            break;
        case AlertLevel::High:
            level_str = "HIGH";
            break;
        case AlertLevel::Critical:
            level_str = "CRITICAL";
            break;
        default:
            level_str = "INFO";
            break;
    }

    std::string msg;
    {
        std::lock_guard<std::mutex> lock(message_mutex_);
        msg = current_message_;
    }

    SendNotification("[" + level_str + "] " + msg);
}

void AlarmManager::SendNotification(const std::string& message)
{
    AlertLevel level = current_level_.load();

    switch (level)
    {
        case AlertLevel::Critical:
            std::cout << "\033[1;91m";
            break;
        case AlertLevel::High:
            std::cout << "\033[1;31m";
            break;
        case AlertLevel::Medium:
            std::cout << "\033[1;33m";
            break;
        case AlertLevel::Low:
            std::cout << "\033[1;34m";
            break;
        default:
            std::cout << "\033[1;32m";
            break;
    }

    std::cout << "[DEFENSE] " << message << "\033[0m" << std::endl;
}

using PacketCallback = std::function<void(const uint8_t* data, int len, const struct pcap_pkthdr* hdr)>;

class PacketCapture
{
public:
    PacketCapture();
    ~PacketCapture();

    bool OpenAdapter(const std::string& adapter_name, bool monitor_mode, int timeout_ms);
    bool OpenOffline(const std::string& filepath);

    bool SetChannel(int channel);
    bool StartCapture(PacketCallback callback);
    bool StopCapture();

    bool IsRunning() const;
    std::vector<std::string> ListAdapters();

    int GetDroppedPackets() const;
    int GetReceivedPackets() const;
    std::string GetError() const;

    static std::vector<std::string> GetAvailableAdapters();

private:
    pcap_t*              pcap_handle_;
    std::atomic<bool>    running_;
    std::thread          capture_thread_;
    std::string          error_msg_;
    mutable std::mutex   error_mutex_;
    PacketCallback       callback_;
    int                  received_count_;
    int                  dropped_count_;

    static void CaptureLoopStatic(uint8_t* user, const struct pcap_pkthdr* hdr, const uint8_t* data);
};

PacketCapture::PacketCapture()
    : pcap_handle_(nullptr)
    , running_(false)
    , received_count_(0)
    , dropped_count_(0)
{
}

PacketCapture::~PacketCapture()
{
    StopCapture();
    if (pcap_handle_)
    {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
}

bool PacketCapture::OpenAdapter(const std::string& adapter_name, bool monitor_mode, int timeout_ms)
{
    if (pcap_handle_)
    {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    pcap_handle_ = pcap_create(adapter_name.c_str(), errbuf);
    if (!pcap_handle_)
    {
        error_msg_ = errbuf;
        return false;
    }

    int status = 0;

    if (monitor_mode)
    {
        status = pcap_set_rfmon(pcap_handle_, 1);
        if (status != 0)
        {
            error_msg_ = "Failed to set monitor mode";
            pcap_close(pcap_handle_);
            pcap_handle_ = nullptr;
            return false;
        }
    }

    status = pcap_set_snaplen(pcap_handle_, 65535);
    if (status != 0)
    {
        error_msg_ = "Failed to set snaplen";
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    status = pcap_set_promisc(pcap_handle_, 1);
    if (status != 0)
    {
        error_msg_ = "Failed to set promiscuous mode";
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    status = pcap_set_timeout(pcap_handle_, timeout_ms);
    if (status != 0)
    {
        error_msg_ = "Failed to set timeout";
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    status = pcap_activate(pcap_handle_);
    if (status != 0)
    {
        error_msg_ = pcap_geterr(pcap_handle_);
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    int dlt = pcap_datalink(pcap_handle_);
    if (dlt != DLT_IEEE802_11_RADIO && dlt != DLT_IEEE802_11)
    {
        error_msg_ = "Unsupported datalink type - requires 802.11 with radiotap";
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    return true;
}

bool PacketCapture::OpenOffline(const std::string& filepath)
{
    if (pcap_handle_)
    {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    pcap_handle_ = pcap_open_offline(filepath.c_str(), errbuf);
    if (!pcap_handle_)
    {
        error_msg_ = errbuf;
        return false;
    }

    return true;
}

bool PacketCapture::SetChannel(int channel)
{
#ifdef _WIN32
    std::string freq_param = std::to_string(channel);
    if (pcap_setfilter(pcap_handle_, nullptr) != 0)
    {
        return false;
    }
    return true;
#else
    static_cast<void>(channel);
    return true;
#endif
}

bool PacketCapture::StartCapture(PacketCallback callback)
{
    if (!pcap_handle_ || running_)
    {
        return false;
    }

    callback_ = callback;
    running_ = true;
    received_count_ = 0;
    dropped_count_ = 0;

    capture_thread_ = std::thread(
        [this]()
        {
            pcap_loop(
                pcap_handle_,
                -1,
                PacketCapture::CaptureLoopStatic,
                reinterpret_cast<uint8_t*>(this)
            );
        }
    );

    return true;
}

bool PacketCapture::StopCapture()
{
    if (!running_)
    {
        return false;
    }

    running_ = false;

    if (pcap_handle_)
    {
        pcap_breakloop(pcap_handle_);
    }

    if (capture_thread_.joinable())
    {
        capture_thread_.join();
    }

    if (pcap_handle_)
    {
        struct pcap_stat stats;
        if (pcap_stats(pcap_handle_, &stats) == 0)
        {
            received_count_ = stats.ps_recv;
            dropped_count_ = stats.ps_drop;
        }
    }

    return true;
}

bool PacketCapture::IsRunning() const
{
    return running_;
}

std::vector<std::string> PacketCapture::ListAdapters()
{
    return GetAvailableAdapters();
}

int PacketCapture::GetDroppedPackets() const
{
    return dropped_count_;
}

int PacketCapture::GetReceivedPackets() const
{
    return received_count_;
}

std::string PacketCapture::GetError() const
{
    std::lock_guard<std::mutex> lock(error_mutex_);
    return error_msg_;
}

std::vector<std::string> PacketCapture::GetAvailableAdapters()
{
    std::vector<std::string> adapters;
    pcap_if_t* alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        return adapters;
    }

    for (pcap_if_t* dev = alldevs; dev; dev = dev->next)
    {
        adapters.push_back(dev->name);
    }

    pcap_freealldevs(alldevs);
    return adapters;
}

void PacketCapture::CaptureLoopStatic(uint8_t* user, const struct pcap_pkthdr* hdr, const uint8_t* data)
{
    PacketCapture* self = reinterpret_cast<PacketCapture*>(user);
    if (self && self->running_)
    {
        self->received_count_++;
        if (self->callback_)
        {
            self->callback_(data, hdr->caplen, hdr);
        }
    }
}

class DefenseEngine
{
public:
    DefenseEngine();
    ~DefenseEngine();

    bool Initialize(const std::string& config_file);
    bool Start();
    bool Stop();
    bool IsRunning() const;
    void Run();

    void PrintStatus() const;
    void PrintDetectedRogueAPs() const;
    void PrintDeauthStats() const;
    void PrintTrafficStats() const;

    ConfigurationManager& GetConfig();
    const ConfigurationManager& GetConfig() const;

private:
    bool                             initialized_;
    std::atomic<bool>                running_;
    std::unique_ptr<ConfigurationManager> config_;
    std::unique_ptr<PacketCapture>   capture_;
    std::unique_ptr<FrameParser>     parser_;
    std::unique_ptr<RogueAPDetector> rogue_detector_;
    std::unique_ptr<DeauthDetector>  deauth_detector_;
    std::unique_ptr<TrafficAnalyzer> traffic_analyzer_;
    std::unique_ptr<AlarmManager>    alarm_manager_;
    std::unique_ptr<Logger>          logger_;

    std::thread                      analysis_thread_;
    int                              frame_count_;
    int                              rogue_ap_count_;
    int                              deauth_alert_count_;
    int                              traffic_alert_count_;

    void PacketHandler(const uint8_t* data, int len, const struct pcap_pkthdr* hdr);
    void AnalysisLoop();
    void HandleRogueAPAlert(const RogueAPResult& result);
    void HandleDeauthAlert(const DeauthAlert& alert);
    void HandleTrafficAlert(const TrafficAlert& alert);
};

DefenseEngine::DefenseEngine()
    : initialized_(false)
    , running_(false)
    , frame_count_(0)
    , rogue_ap_count_(0)
    , deauth_alert_count_(0)
    , traffic_alert_count_(0)
{
}

DefenseEngine::~DefenseEngine()
{
    Stop();
}

bool DefenseEngine::Initialize(const std::string& config_file)
{
    config_ = std::make_unique<ConfigurationManager>();

    if (!config_->LoadFromFile(config_file))
    {
        std::cerr << "Failed to load configuration from: " << config_file << std::endl;
        std::cerr << "Using default configuration." << std::endl;
    }

    logger_ = std::make_unique<Logger>(config_->GetLoggingConfig());

    logger_->Log(LogLevel::Info, "Initializing Mahoraga Defense Engine");
    logger_->Log(LogLevel::Info, "Configuration loaded successfully");

    parser_ = std::make_unique<FrameParser>();

    rogue_detector_ = std::make_unique<RogueAPDetector>(
        config_->GetBSSIDWhitelist(),
        config_->GetBSSIDBlacklist(),
        config_->GetSSIDWhitelist(),
        config_->GetSSIDBlacklist()
    );

    deauth_detector_ = std::make_unique<DeauthDetector>(
        config_->GetDeauthThreshold(),
        config_->GetDeauthWindowSec()
    );

    traffic_analyzer_ = std::make_unique<TrafficAnalyzer>();

    alarm_manager_ = std::make_unique<AlarmManager>(
        config_->GetAlarmConfig().alarm_enabled,
        config_->GetAlarmConfig().alarm_duration_ms,
        config_->GetAlarmConfig().alarm_interval_ms,
        config_->GetLEDConfig().led_enabled,
        config_->GetLEDConfig().led_pin,
        config_->GetDisplayConfig().display_enabled
    );

    capture_ = std::make_unique<PacketCapture>();

    initialized_ = true;

    logger_->Log(LogLevel::Info, "Defense Engine initialization complete");

    return true;
}

bool DefenseEngine::Start()
{
    if (!initialized_)
    {
        logger_->Log(LogLevel::Critical, "Cannot start - engine not initialized");
        return false;
    }

    if (running_)
    {
        logger_->Log(LogLevel::Warning, "Engine is already running");
        return false;
    }

    auto adapters = PacketCapture::GetAvailableAdapters();

    if (adapters.empty())
    {
        logger_->Log(LogLevel::Critical, "No network adapters found for packet capture");
        return false;
    }

    std::string adapter_name = adapters[0];
    logger_->Log(LogLevel::Info, "Opening adapter: " + adapter_name);

    if (!capture_->OpenAdapter(adapter_name, true, 1000))
    {
        logger_->Log(LogLevel::Warning,
            "Monitor mode failed on " + adapter_name + " - trying promiscuous mode");

        if (!capture_->OpenAdapter(adapter_name, false, 1000))
        {
            logger_->Log(LogLevel::Critical,
                "Failed to open adapter: " + adapter_name +
                " - " + capture_->GetError());
            return false;
        }
    }

    logger_->Log(LogLevel::Info, "Packet capture initialized on: " + adapter_name);

    PacketCallback callback = [this](const uint8_t* data, int len,
                                     const struct pcap_pkthdr* hdr)
    {
        this->PacketHandler(data, len, hdr);
    };

    if (!capture_->StartCapture(callback))
    {
        logger_->Log(LogLevel::Critical, "Failed to start packet capture");
        return false;
    }

    running_ = true;

    analysis_thread_ = std::thread(&DefenseEngine::AnalysisLoop, this);

    logger_->Log(LogLevel::Info, "Defense Engine started - monitoring network traffic");

    return true;
}

bool DefenseEngine::Stop()
{
    if (!running_)
    {
        return false;
    }

    running_ = false;

    if (capture_)
    {
        capture_->StopCapture();
    }

    if (analysis_thread_.joinable())
    {
        analysis_thread_.join();
    }

    logger_->Log(LogLevel::Info, "Defense Engine stopped");

    logger_->Log(LogLevel::Info,
        "Session summary - Frames: " + std::to_string(frame_count_) +
        ", Rogue APs: " + std::to_string(rogue_ap_count_) +
        ", Deauth Alerts: " + std::to_string(deauth_alert_count_) +
        ", Traffic Alerts: " + std::to_string(traffic_alert_count_));

    return true;
}

bool DefenseEngine::IsRunning() const
{
    return running_.load();
}

void DefenseEngine::Run()
{
    if (!Start())
    {
        return;
    }

    logger_->Log(LogLevel::Info, "Defense Engine is active. Press Ctrl+C to stop.");

    while (running_)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void DefenseEngine::PacketHandler(const uint8_t* data, int len,
                                   const struct pcap_pkthdr* hdr)
{
    static_cast<void>(hdr);

    frame_count_++;

    auto parsed_frame = parser_->Parse(data, len);

    if (!parsed_frame)
    {
        return;
    }

    ParsedFrame& frame = parsed_frame.value();

    if (frame.is_beacon)
    {
        RogueAPResult rogue_result = rogue_detector_->AnalyzeBeacon(frame);

        if (rogue_result.is_rogue)
        {
            rogue_ap_count_++;
            HandleRogueAPAlert(rogue_result);
        }
    }

    if (frame.is_deauth || frame.is_disassociation)
    {
        DeauthAlert deauth_alert = deauth_detector_->AnalyzeFrame(frame);

        if (deauth_alert.is_flood)
        {
            deauth_alert_count_++;
            HandleDeauthAlert(deauth_alert);
        }
    }

    TrafficAlert traffic_alert = traffic_analyzer_->AnalyzeFrame(frame);

    if (traffic_alert.anomaly != AnomalyType::None)
    {
        traffic_alert_count_++;
        HandleTrafficAlert(traffic_alert);
    }
}

void DefenseEngine::AnalysisLoop()
{
    while (running_)
    {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        int current_rate = deauth_detector_->GetCurrentRate();
        int pps = traffic_analyzer_->GetPacketsPerSecond();

        if (current_rate > 0)
        {
            logger_->Log(LogLevel::Debug,
                "Deauth rate: " + std::to_string(current_rate) +
                " pps, Total PPS: " + std::to_string(pps));
        }
    }
}

void DefenseEngine::HandleRogueAPAlert(const RogueAPResult& result)
{
    std::string mac_str = FrameParser::MacToString(result.bssid);

    std::string details = "Rogue AP - SSID: " + result.ssid +
                          ", BSSID: " + mac_str +
                          ", Channel: " + std::to_string(result.channel) +
                          ", Signal: " + std::to_string(result.signal_dbm) + " dBm" +
                          ", Details: " + result.details;

    logger_->LogAlert("ROGUE_AP", details);

    alarm_manager_->TriggerAlert(result.alert_level, details);

    std::ostringstream console;
    console << "\033[1;31m";
    console << "[ROGUE AP DETECTED]"
            << " SSID: " << result.ssid
            << " BSSID: " << mac_str
            << " CH: " << result.channel
            << " Signal: " << result.signal_dbm << " dBm"
            << " Level: " << static_cast<int>(result.alert_level);
    console << "\033[0m";
    std::cout << console.str() << std::endl;
}

void DefenseEngine::HandleDeauthAlert(const DeauthAlert& alert)
{
    std::string src_mac = FrameParser::MacToString(alert.source_mac);
    std::string tgt_mac = FrameParser::MacToString(alert.target_mac);
    std::string bssid_mac = FrameParser::MacToString(alert.bssid);

    std::string details = "Deauth Flood - Source: " + src_mac +
                          ", Target: " + tgt_mac +
                          ", BSSID: " + bssid_mac +
                          ", Rate: " + std::to_string(alert.packet_rate) + " pps" +
                          ", Reason: " + DeauthDetector::ReasonCodeToString(alert.reason_code);

    logger_->LogAlert("DEAUTH_FLOOD", details);

    alarm_manager_->TriggerAlert(AlertLevel::High, details);

    std::ostringstream console;
    console << "\033[1;33m";
    console << "[DEAUTH FLOOD DETECTED]"
            << " Source: " << src_mac
            << " Target: " << tgt_mac
            << " Rate: " << alert.packet_rate << " pps";
    console << "\033[0m";
    std::cout << console.str() << std::endl;
}

void DefenseEngine::HandleTrafficAlert(const TrafficAlert& alert)
{
    std::string src_mac = FrameParser::MacToString(alert.source_mac);

    std::string details = alert.description +
                          ", Source: " + src_mac +
                          ", Rate: " + std::to_string(alert.rate) + " pps";

    logger_->LogAlert("TRAFFIC_ANOMALY", details);

    alarm_manager_->TriggerAlert(alert.severity, details);

    std::ostringstream console;
    console << "\033[1;34m";
    console << "[TRAFFIC ANOMALY] " << alert.description
            << " Source: " << src_mac;
    console << "\033[0m";
    std::cout << console.str() << std::endl;
}

void DefenseEngine::PrintStatus() const
{
    std::cout << "\n=== MAHORAGA DEFENSE ENGINE STATUS ===" << std::endl;
    std::cout << "Status: " << (running_ ? "ACTIVE" : "STOPPED") << std::endl;
    std::cout << "Total Frames Captured: " << frame_count_ << std::endl;
    std::cout << "Rogue AP Detections: " << rogue_ap_count_ << std::endl;
    std::cout << "Deauth Flood Alerts: " << deauth_alert_count_ << std::endl;
    std::cout << "Traffic Anomalies: " << traffic_alert_count_ << std::endl;
    std::cout << "Current Deauth Rate: "
              << deauth_detector_->GetCurrentRate() << " pps" << std::endl;
    std::cout << "Current PPS: "
              << traffic_analyzer_->GetPacketsPerSecond() << std::endl;
    std::cout << "Frames: MGMT:" << traffic_analyzer_->GetManagementFrameCount()
              << " CTRL:" << traffic_analyzer_->GetControlFrameCount()
              << " DATA:" << traffic_analyzer_->GetDataFrameCount();
    std::cout << "\n======================================\n" << std::endl;
}

void DefenseEngine::PrintDetectedRogueAPs() const
{
    auto rogues = rogue_detector_->GetDetectedRogueAPs();

    std::cout << "\n=== ROGUE ACCESS POINTS ===" << std::endl;

    if (rogues.empty())
    {
        std::cout << "No rogue APs detected." << std::endl;
    }
    else
    {
        for (const auto& rogue : rogues)
        {
            std::string mac_str = FrameParser::MacToString(rogue.bssid);
            std::cout << "SSID: " << rogue.ssid
                      << " BSSID: " << mac_str
                      << " CH: " << rogue.channel
                      << " Signal: " << rogue.signal_dbm << " dBm"
                      << " Alert: " << rogue.details
                      << std::endl;
        }
    }

    std::cout << "============================\n" << std::endl;
}

void DefenseEngine::PrintDeauthStats() const
{
    std::cout << "\n=== DEAUTHENTICATION STATISTICS ===" << std::endl;
    std::cout << "Current Deauth Rate: "
              << deauth_detector_->GetCurrentRate() << " pps" << std::endl;
    std::cout << "Threshold: "
              << config_->GetDeauthThreshold() << " pps" << std::endl;
    std::cout << "Alert Count: " << deauth_alert_count_ << std::endl;
    std::cout << "====================================\n" << std::endl;
}

void DefenseEngine::PrintTrafficStats() const
{
    std::cout << "\n=== TRAFFIC STATISTICS ===" << std::endl;
    std::cout << "Total Frames: " << traffic_analyzer_->GetTotalFrameCount() << std::endl;
    std::cout << "Management Frames: " << traffic_analyzer_->GetManagementFrameCount() << std::endl;
    std::cout << "Control Frames: " << traffic_analyzer_->GetControlFrameCount() << std::endl;
    std::cout << "Data Frames: " << traffic_analyzer_->GetDataFrameCount() << std::endl;
    std::cout << "Current PPS: " << traffic_analyzer_->GetPacketsPerSecond() << std::endl;
    std::cout << "Traffic Alerts: " << traffic_alert_count_ << std::endl;
    std::cout << "==========================\n" << std::endl;
}

ConfigurationManager& DefenseEngine::GetConfig()
{
    return *config_;
}

const ConfigurationManager& DefenseEngine::GetConfig() const
{
    return *config_;
}

}

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

#ifdef _WIN32
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

