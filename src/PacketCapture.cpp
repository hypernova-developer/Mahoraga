#include "PacketCapture.h"

#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <pcap.h>
#include <cstring>

namespace mahoraga
{

PacketCapture::PacketCapture()
    : pcap_handle_(nullptr)
    , running_(false)
    , received_count_(0)
    , dropped_count_(0)
{
}

PacketCapture::~PacketCapture()
{
    StopCapture();
    if (pcap_handle_)
    {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
}

bool PacketCapture::OpenAdapter(const std::string& adapter_name, bool monitor_mode, int timeout_ms)
{
    if (pcap_handle_)
    {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    pcap_handle_ = pcap_create(adapter_name.c_str(), errbuf);
    if (!pcap_handle_)
    {
        error_msg_ = errbuf;
        return false;
    }

    int status = 0;

    if (monitor_mode)
    {
        status = pcap_set_rfmon(pcap_handle_, 1);
        if (status != 0)
        {
            error_msg_ = "Failed to set monitor mode";
            pcap_close(pcap_handle_);
            pcap_handle_ = nullptr;
            return false;
        }
    }

    status = pcap_set_snaplen(pcap_handle_, 65535);
    if (status != 0)
    {
        error_msg_ = "Failed to set snaplen";
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    status = pcap_set_promisc(pcap_handle_, 1);
    if (status != 0)
    {
        error_msg_ = "Failed to set promiscuous mode";
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    status = pcap_set_timeout(pcap_handle_, timeout_ms);
    if (status != 0)
    {
        error_msg_ = "Failed to set timeout";
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    status = pcap_activate(pcap_handle_);
    if (status != 0)
    {
        error_msg_ = pcap_geterr(pcap_handle_);
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    int dlt = pcap_datalink(pcap_handle_);
    if (dlt != DLT_IEEE802_11_RADIO && dlt != DLT_IEEE802_11)
    {
        error_msg_ = "Unsupported datalink type - requires 802.11 with radiotap";
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }

    return true;
}

bool PacketCapture::OpenOffline(const std::string& filepath)
{
    if (pcap_handle_)
    {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    pcap_handle_ = pcap_open_offline(filepath.c_str(), errbuf);
    if (!pcap_handle_)
    {
        error_msg_ = errbuf;
        return false;
    }

    return true;
}

bool PacketCapture::SetChannel(int channel)
{
#ifdef _WIN32
    std::string freq_param = std::to_string(channel);
    if (pcap_setfilter(pcap_handle_, nullptr) != 0)
    {
        return false;
    }
    return true;
#else
    // On Linux, use iw or nl80211 to set channel
    // This is platform-specific; for now we return true
    // and expect the user to have the adapter on the right channel
    static_cast<void>(channel);
    return true;
#endif
}

bool PacketCapture::StartCapture(PacketCallback callback)
{
    if (!pcap_handle_ || running_)
    {
        return false;
    }

    callback_ = callback;
    running_ = true;
    received_count_ = 0;
    dropped_count_ = 0;

    capture_thread_ = std::thread(
        [this]()
        {
            pcap_loop(
                pcap_handle_,
                -1,
                PacketCapture::CaptureLoopStatic,
                reinterpret_cast<uint8_t*>(this)
            );
        }
    );

    return true;
}

bool PacketCapture::StopCapture()
{
    if (!running_)
    {
        return false;
    }

    running_ = false;

    if (pcap_handle_)
    {
        pcap_breakloop(pcap_handle_);
    }

    if (capture_thread_.joinable())
    {
        capture_thread_.join();
    }

    if (pcap_handle_)
    {
        struct pcap_stat stats;
        if (pcap_stats(pcap_handle_, &stats) == 0)
        {
            received_count_ = stats.ps_recv;
            dropped_count_ = stats.ps_drop;
        }
    }

    return true;
}

bool PacketCapture::IsRunning() const
{
    return running_;
}

std::vector<std::string> PacketCapture::ListAdapters()
{
    return GetAvailableAdapters();
}

int PacketCapture::GetDroppedPackets() const
{
    return dropped_count_;
}

int PacketCapture::GetReceivedPackets() const
{
    return received_count_;
}

std::string PacketCapture::GetError() const
{
    std::lock_guard<std::mutex> lock(error_mutex_);
    return error_msg_;
}

std::vector<std::string> PacketCapture::GetAvailableAdapters()
{
    std::vector<std::string> adapters;
    pcap_if_t* alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        return adapters;
    }

    for (pcap_if_t* dev = alldevs; dev; dev = dev->next)
    {
        adapters.push_back(dev->name);
    }

    pcap_freealldevs(alldevs);
    return adapters;
}

void PacketCapture::CaptureLoopStatic(uint8_t* user, const struct pcap_pkthdr* hdr, const uint8_t* data)
{
    PacketCapture* self = reinterpret_cast<PacketCapture*>(user);
    if (self && self->running_)
    {
        self->received_count_++;
        if (self->callback_)
        {
            self->callback_(data, hdr->caplen, hdr);
        }
    }
}

}

