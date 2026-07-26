#ifndef MAHORAGA_DEFENSE_ENGINE_H
#define MAHORAGA_DEFENSE_ENGINE_H

#include <string>
#include <memory>
#include <atomic>
#include <chrono>
#include <thread>
#include "ConfigurationManager.h"
#include "PacketCapture.h"
#include "FrameParser.h"
#include "RogueAPDetector.h"
#include "DeauthDetector.h"
#include "TrafficAnalyzer.h"
#include "AlarmManager.h"
#include "Logger.h"

namespace mahoraga
{

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

}

#endif

