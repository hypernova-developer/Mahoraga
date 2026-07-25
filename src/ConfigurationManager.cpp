#include "ConfigurationManager.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cctype>

namespace mahoraga
{

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

}

