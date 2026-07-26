#ifndef MAHORAGA_FRAME_PARSER_H
#define MAHORAGA_FRAME_PARSER_H

#include <cstdint>
#include <string>
#include <array>
#include <vector>
#include <optional>
#include "../include/80211.h"

namespace mahoraga
{

struct ParsedFrame
{
    FrameType                    frame_type;
    uint8_t                      subtype;
    std::array<uint8_t, 6>      transmitter_addr;
    std::array<uint8_t, 6>      receiver_addr;
    std::array<uint8_t, 6>      bssid;
    std::string                  ssid;
    int                          channel;
    int                          signal_dbm;
    uint16_t                     reason_code;
    uint64_t                     timestamp_us;
    bool                         is_deauth;
    bool                         is_disassociation;
    bool                         is_beacon;
};

class FrameParser
{
public:
    FrameParser();

    std::optional<ParsedFrame> Parse(const uint8_t* data, int length) const;

    static std::string MacToString(const std::array<uint8_t, 6>& mac);
    static bool MacsEqual(const std::array<uint8_t, 6>& a, const std::array<uint8_t, 6>& b);

private:
    static FrameType GetFrameType(const FrameControl& fc) ;
    static uint8_t GetSubtype(const FrameControl& fc) ;
    static int ParseRadioTapHeader(const uint8_t* data, int length, int& signal_dbm) ;
    static std::string ParseSSIDFromBeacon(const uint8_t* body, int body_length) ;
    static uint16_t ParseReasonCode(const uint8_t* body, int body_length) ;
};

}

#endif

