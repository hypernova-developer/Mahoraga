#ifndef MAHORAGA_DEAUTH_DETECTOR_H
#define MAHORAGA_DEAUTH_DETECTOR_H

#include <cstdint>
#include <vector>
#include <array>
#include <deque>
#include <chrono>
#include <mutex>
#include <atomic>
#include <string>
#include "../include/80211.h"
#include "FrameParser.h"

namespace mahoraga
{

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

}

#endif

