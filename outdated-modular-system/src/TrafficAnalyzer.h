#ifndef MAHORAGA_TRAFFIC_ANALYZER_H
#define MAHORAGA_TRAFFIC_ANALYZER_H

#include <cstdint>
#include <atomic>
#include <chrono>
#include <string>
#include <array>
#include <deque>
#include <map>
#include <mutex>
#include "../include/80211.h"
#include "FrameParser.h"
#include "RogueAPDetector.h"

namespace mahoraga
{

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

}

#endif

