#include "DeauthDetector.h"
#include <algorithm>
#include <cstring>
#include <sstream>

namespace mahoraga
{

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

}

