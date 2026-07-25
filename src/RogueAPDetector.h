#ifndef MAHORAGA_ROGUE_AP_DETECTOR_H
#define MAHORAGA_ROGUE_AP_DETECTOR_H

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include "../include/80211.h"
#include "FrameParser.h"

namespace mahoraga
{

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

}

#endif

