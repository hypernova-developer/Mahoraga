#ifndef MAHORAGA_CONFIGURATION_MANAGER_H
#define MAHORAGA_CONFIGURATION_MANAGER_H

#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include "../include/80211.h"

namespace mahoraga
{

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

}

#endif

