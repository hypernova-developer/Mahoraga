#include "TrafficAnalyzer.h"
#include <cstring>
#include <algorithm>

namespace mahoraga
{

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

}

