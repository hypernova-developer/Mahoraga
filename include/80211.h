#ifndef MAHORAGA_80211_H
#define MAHORAGA_80211_H

#include <cstdint>

namespace mahoraga
{

enum class FrameType : uint8_t
{
    Management     = 0x00,
    Control        = 0x01,
    Data           = 0x02
};

enum class ManagementSubtype : uint8_t
{
    AssociationRequest      = 0x00,
    AssociationResponse     = 0x01,
    ReassociationRequest    = 0x02,
    ReassociationResponse   = 0x03,
    ProbeRequest            = 0x04,
    ProbeResponse           = 0x05,
    Beacon                  = 0x08,
    ATIM                    = 0x09,
    Disassociation          = 0x0A,
    Authentication          = 0x0B,
    Deauthentication        = 0x0C,
    Action                  = 0x0D
};

enum class ControlSubtype : uint8_t
{
    Trigger       = 0x02,
    Beamforming   = 0x03,
    VHT_NDP_Ann   = 0x04,
    ControlFrame  = 0x07,
    BlockAckReq   = 0x08,
    BlockAck      = 0x09,
    PS_Poll       = 0x0A,
    RTS           = 0x0B,
    CTS           = 0x0C,
    ACK           = 0x0D,
    CF_End        = 0x0E,
    CF_End_ACK    = 0x0F
};

struct RadioTapHeader
{
    uint8_t  version;
    uint8_t  pad;
    uint16_t length;
    uint32_t present;
};

struct FrameControl
{
    uint8_t protocol_version : 2;
    uint8_t type             : 2;
    uint8_t subtype          : 4;
    uint8_t to_ds            : 1;
    uint8_t from_ds          : 1;
    uint8_t more_frag        : 1;
    uint8_t retry            : 1;
    uint8_t power_mgmt       : 1;
    uint8_t more_data        : 1;
    uint8_t protected_frame  : 1;
    uint8_t order            : 1;
};

struct ManagementFrameHeader
{
    FrameControl frame_control;
    uint16_t     duration;
    uint8_t      da[6];
    uint8_t      sa[6];
    uint8_t      bssid[6];
    uint16_t     seq_ctrl;
};

struct DeauthFrame
{
    ManagementFrameHeader header;
    uint16_t              reason_code;
};

struct BeaconFrame
{
    ManagementFrameHeader header;
    uint64_t              timestamp;
    uint16_t              beacon_interval;
    uint16_t              capability;
};

struct SSIDElement
{
    uint8_t element_id;
    uint8_t length;
    uint8_t ssid[32];
};

constexpr int MAC_ADDR_LEN      = 6;
constexpr int MAX_SSID_LEN      = 32;
constexpr int MAX_CHANNELS      = 64;
constexpr int MAX_WHITELIST     = 256;
constexpr int MAX_BLACKLIST     = 256;
constexpr int RING_BUFFER_SIZE  = 4096;
constexpr int MAX_DEAUTH_HISTORY = 1024;

}

#endif

