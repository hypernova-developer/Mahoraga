#include "RogueAPDetector.h"
#include <algorithm>
#include <cstring>
#include <iostream>

namespace mahoraga
{

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

}

