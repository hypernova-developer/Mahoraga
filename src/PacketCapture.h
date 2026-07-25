#ifndef MAHORAGA_PACKET_CAPTURE_H
#define MAHORAGA_PACKET_CAPTURE_H

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <memory>
#include <cstdint>
#include "../include/80211.h"

struct pcap_t;
struct pcap_pkthdr;

namespace mahoraga
{

using PacketCallback = std::function<void(const uint8_t* data, int len, const struct pcap_pkthdr* hdr)>;

class PacketCapture
{
public:
    PacketCapture();
    ~PacketCapture();

    bool OpenAdapter(const std::string& adapter_name, bool monitor_mode, int timeout_ms);
    bool OpenOffline(const std::string& filepath);

    bool SetChannel(int channel);
    bool StartCapture(PacketCallback callback);
    bool StopCapture();

    bool IsRunning() const;
    std::vector<std::string> ListAdapters();

    int GetDroppedPackets() const;
    int GetReceivedPackets() const;
    std::string GetError() const;

    static std::vector<std::string> GetAvailableAdapters();

private:
    pcap_t*              pcap_handle_;
    std::atomic<bool>    running_;
    std::thread          capture_thread_;
    std::string          error_msg_;
    std::mutex           error_mutex_;
    PacketCallback       callback_;
    int                  received_count_;
    int                  dropped_count_;

    static void CaptureLoopStatic(uint8_t* user, const struct pcap_pkthdr* hdr, const uint8_t* data);
};

}

#endif

