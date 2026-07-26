#include "FrameParser.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace mahoraga
{

FrameParser::FrameParser()
{
}

std::optional<ParsedFrame> FrameParser::Parse(const uint8_t* data, int length) const
{
    if (!data || length < static_cast<int>(sizeof(RadioTapHeader) + sizeof(FrameControl)))
    {
        return std::nullopt;
    }

    ParsedFrame frame{};
    frame.channel = 0;
    frame.signal_dbm = 0;
    frame.reason_code = 0;
    frame.timestamp_us = 0;
    frame.is_deauth = false;
    frame.is_disassociation = false;
    frame.is_beacon = false;

    std::memset(frame.transmitter_addr.data(), 0, 6);
    std::memset(frame.receiver_addr.data(), 0, 6);
    std::memset(frame.bssid.data(), 0, 6);

    int offset = ParseRadioTapHeader(data, length, frame.signal_dbm);
    if (offset < 0 || offset >= length)
    {
        return std::nullopt;
    }

    if (static_cast<size_t>(length - offset) < sizeof(FrameControl))
    {
        return std::nullopt;
    }

    FrameControl fc;
    std::memcpy(&fc, data + offset, sizeof(FrameControl));

    frame.frame_type = GetFrameType(fc);
    frame.subtype = GetSubtype(fc);

    uint8_t frame_subtype = fc.subtype;
    uint8_t frame_type_bits = fc.type;

    offset += sizeof(FrameControl);

    if (frame_type_bits == 0x00)
    {
        if (offset + static_cast<int>(sizeof(ManagementFrameHeader) - sizeof(FrameControl)) > length)
        {
            return std::nullopt;
        }

        ManagementFrameHeader mgmt_hdr;
        std::memcpy(&mgmt_hdr, data + offset - sizeof(FrameControl), sizeof(ManagementFrameHeader));

        std::memcpy(frame.transmitter_addr.data(), mgmt_hdr.sa, 6);
        std::memcpy(frame.receiver_addr.data(), mgmt_hdr.da, 6);
        std::memcpy(frame.bssid.data(), mgmt_hdr.bssid, 6);

        int header_size = sizeof(ManagementFrameHeader) - sizeof(FrameControl);
        offset += header_size;

        int body_length = length - offset;

        if (frame_subtype == 0x08 || frame_subtype == 0x05)
        {
            frame.is_beacon = true;
            if (offset + 12 <= length)
            {
                frame.ssid = ParseSSIDFromBeacon(data + offset, body_length);
            }
        }
        else if (frame_subtype == 0x0C)
        {
            frame.is_deauth = true;
            if (body_length >= 2)
            {
                frame.reason_code = ParseReasonCode(data + offset, body_length);
            }
        }
        else if (frame_subtype == 0x0A)
        {
            frame.is_disassociation = true;
            if (body_length >= 2)
            {
                frame.reason_code = ParseReasonCode(data + offset, body_length);
            }
        }
    }
    else if (frame_type_bits == 0x01)
    {
        if (offset + 10 <= length)
        {
            uint16_t fc_duration;
            std::memcpy(&fc_duration, data + offset - sizeof(FrameControl) + 2, 2);

            uint8_t addr1[6];
            uint8_t addr2[6];
            std::memcpy(addr1, data + offset - sizeof(FrameControl) + 4, 6);

            if (offset - sizeof(FrameControl) + 10 + 6 <= length)
            {
                std::memcpy(addr2, data + offset - sizeof(FrameControl) + 10, 6);
                std::memcpy(frame.transmitter_addr.data(), addr2, 6);
            }
            std::memcpy(frame.receiver_addr.data(), addr1, 6);
            std::memcpy(frame.bssid.data(), addr1, 6);
        }
    }
    else if (frame_type_bits == 0x02)
    {
        if (offset + 10 <= length)
        {
            uint8_t addr1[6];
            uint8_t addr2[6];
            std::memcpy(addr1, data + offset - sizeof(FrameControl) + 4, 6);

            if (offset - sizeof(FrameControl) + 10 + 6 <= length)
            {
                std::memcpy(addr2, data + offset - sizeof(FrameControl) + 10, 6);
                std::memcpy(frame.transmitter_addr.data(), addr2, 6);
            }
            std::memcpy(frame.receiver_addr.data(), addr1, 6);
            std::memcpy(frame.bssid.data(), addr1, 6);
        }
    }

    return frame;
}

std::string FrameParser::MacToString(const std::array<uint8_t, 6>& mac)
{
    std::ostringstream oss;
    for (int i = 0; i < 6; i++)
    {
        if (i > 0)
        {
            oss << ":";
        }
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(mac[i]);
    }
    return oss.str();
}

bool FrameParser::MacsEqual(const std::array<uint8_t, 6>& a, const std::array<uint8_t, 6>& b)
{
    return std::memcmp(a.data(), b.data(), 6) == 0;
}

FrameType FrameParser::GetFrameType(const FrameControl& fc)
{
    switch (fc.type)
    {
        case 0x00:
            return FrameType::Management;
        case 0x01:
            return FrameType::Control;
        case 0x02:
            return FrameType::Data;
        default:
            return FrameType::Management;
    }
}

uint8_t FrameParser::GetSubtype(const FrameControl& fc)
{
    return fc.subtype;
}

int FrameParser::ParseRadioTapHeader(const uint8_t* data, int length, int& signal_dbm)
{
    if (length < static_cast<int>(sizeof(RadioTapHeader)))
    {
        return -1;
    }

    RadioTapHeader radiotap;
    std::memcpy(&radiotap, data, sizeof(RadioTapHeader));

    if (radiotap.length < sizeof(RadioTapHeader) || radiotap.length > static_cast<uint16_t>(length))
    {
        return -1;
    }

    signal_dbm = 0;

    uint32_t present = radiotap.present;
    int offset = sizeof(RadioTapHeader);

    if (present & (1 << 0))
    {
        if (offset + 8 <= radiotap.length)
        {
            offset += 8;
        }
    }

    if (present & (1 << 1))
    {
        if (offset + 1 <= radiotap.length)
        {
            offset += 1;
        }
    }

    if (present & (1 << 2))
    {
        if (offset + 1 <= radiotap.length)
        {
            signal_dbm = static_cast<int>(*reinterpret_cast<const int8_t*>(data + offset));
            offset += 1;
        }
    }

    if (present & (1 << 3))
    {
        if (offset + 1 <= radiotap.length)
        {
            offset += 1;
        }
    }

    if (present & (1 << 4))
    {
        if (offset + 1 <= radiotap.length)
        {
            offset += 1;
        }
    }

    if (present & (1 << 5))
    {
        if (offset + 1 <= radiotap.length)
        {
            offset += 1;
        }
    }

    if (present & (1 << 6))
    {
        if (offset + 4 <= radiotap.length)
        {
            offset += 4;
        }
    }

    return radiotap.length;
}

std::string FrameParser::ParseSSIDFromBeacon(const uint8_t* body, int body_length)
{
    int offset = 12;

    while (offset + 2 <= body_length)
    {
        uint8_t element_id = body[offset];
        uint8_t element_len = body[offset + 1];

        if (element_id == 0x00)
        {
            if (element_len > 0 && offset + 2 + element_len <= static_cast<size_t>(body_length))
            {
                return std::string(
                    reinterpret_cast<const char*>(body + offset + 2),
                    std::min(static_cast<int>(element_len), 32)
                );
            }
            break;
        }

        offset += 2 + element_len;
    }

    return "";
}

uint16_t FrameParser::ParseReasonCode(const uint8_t* body, int body_length)
{
    if (body_length < 2)
    {
        return 0;
    }

    uint16_t reason;
    std::memcpy(&reason, body, sizeof(uint16_t));
    return reason;
}

}

