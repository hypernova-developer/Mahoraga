#include "DefenseEngine.h"
#include <iostream>
#include <sstream>

namespace mahoraga
{

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

