# Mahoraga Defense Engine

**Network Defense & Auditing System** — A real-time active threat detection and network defense system that monitors wireless networks for rogue access points, deauthentication/disassociation attacks, and abnormal traffic patterns.

## System Purpose

This software is an **active threat detection and network defense (Network Defense & Auditing)** system that runs directly on real hardware and network cards. It focuses on detecting and logging/generating alarms for:

- **Rogue Access Points (Rogue APs)** — Unauthorized APs, Evil Twin attacks, BSSID spoofing
- **Deauth/Disassociation Packet Attacks** — Flood detection and rate analysis
- **Abnormal Network Traffic** — High packet rate anomalies, beacon floods

## Architecture

```
                        +-----------------------+
                        |    DefenseEngine      |
                        |  (Core Orchestrator)  |
                        +----------+------------+
                                   |
          +------------------------+------------------------+
          |                        |                        |
          v                        v                        v
+-------------------+   +-------------------+   +-------------------+
|  PacketCapture    |   |  FrameParser      |   |  Configuration   |
|  (pcap/libpcap)   |-->|  (802.11 Parse)   |   |  Manager         |
+-------------------+   +-------------------+   +-------------------+
                                |
            +-------------------+-------------------+
            |                   |                   |
            v                   v                   v
+-------------------+  +-------------------+  +-------------------+
| RogueAPDetector   |  | DeauthDetector    |  | TrafficAnalyzer   |
| (Beacon Analysis) |  | (Flood Detection) |  | (Anomaly Detect)  |
+-------------------+  +-------------------+  +-------------------+
            |                   |                   |
            +-------------------+-------------------+
                                |
                                v
                    +-----------------------+
                    |    AlarmManager       |
                    |  (Siren/LED/Display)  |
                    +-----------------------+
                                |
                                v
                    +-----------------------+
                    |      Logger           |
                    |  (Serial/WebUI/SD)    |
                    +-----------------------+
```

## Requirements

### Windows
- MinGW GCC (g++) with C++20 support
- Npcap or WinPcap (with SDK for development headers)
- Windows SDK

### Linux
- GCC (g++) with C++20 support
- libpcap-dev
- pthreads

## Build Instructions

The project supports two build modes:

- **Monolithic** (default): Compiles the single merged file `mahoraga_latest.cpp`
- **Modular**: Compiles all individual source files from `src/`

### Windows

```batch
cd scripts
build.bat
# Choose option 1 for monolithic or 2 for modular
```

Direct compilation (monolithic):
```batch
g++ -std=c++20 -O2 -Wall mahoraga_latest.cpp -o mahoraga.exe -lwpcap -lws2_32
```

### Linux

```bash
cd scripts
chmod +x build.sh
./build.sh
# Choose option 1 for monolithic or 2 for modular
```

Direct compilation (monolithic):
```bash
g++ -std=c++20 -O2 -Wall mahoraga_latest.cpp -o mahoraga -lpcap -pthread
```

## Configuration

Edit `config/mahoraga.conf` to customize:

| Section | Parameter | Description |
|---------|-----------|-------------|
| `[channels]` | `channels_2ghz`, `channels_5ghz` | Wi-Fi band/channel selection |
| `[bssid_whitelist]` | MAC addresses | Authorized BSSIDs |
| `[bssid_blacklist]` | MAC addresses | Blocked BSSIDs |
| `[ssid_whitelist]` | SSID names | Authorized SSIDs |
| `[ssid_blacklist]` | SSID names | Blocked SSIDs |
| `[deauth_detection]` | `deauth_threshold` | Packets/sec flood threshold |
| `[logging]` | `serial_enabled`, `serial_port`, `serial_baud`, `webui_enabled`, `webui_port`, `sdcard_enabled`, `sdcard_path` | Logging configuration |
| `[alarm]` | `alarm_enabled`, `alarm_duration_ms`, `alarm_interval_ms` | Alarm/siren parameters |
| `[led]` | `led_enabled`, `led_pin` | LED notification |
| `[display]` | `display_enabled` | Display notification |

## Usage

```bash
# Run with default config
./mahoraga

# Run with custom config file
./mahoraga /path/to/custom.conf
```

## Dynamic Parameters at Runtime

All parameters can be defined dynamically via the configuration file. The system loads the configuration at startup and applies all settings immediately. Configuration can be updated at runtime through the `ConfigurationManager` API.

## Detection Capabilities

### Rogue AP Detection
- BSSID/SSID whitelist enforcement
- Blacklist matching
- Evil Twin detection (multiple APs with same SSID)
- BSSID spoofing detection

### Deauth/Disassociation Detection
- Per-second packet rate monitoring
- Configurable flood threshold
- Reason code analysis
- Suspicious pattern recognition

### Traffic Anomaly Detection
- Per-second packet rate calculation
- Beacon flood detection
- Frame type distribution analysis
- Source MAC flow tracking

## Logging

The system supports three logging outputs:
1. **Serial Port** — Configurable baud rate and port selection
2. **WebUI** — Built-in web interface (port configurable)
3. **SD Card** — File-based logging to external storage

## Alarm System

When threats are detected, the alarm system activates:
- **Siren/Alarm** — Audible alert with configurable duration and interval
- **LED** — Visual notification (GPIO pin configurable)
- **Display** — On-screen/display notification

## License

GNU General Public License v3.0 (GPLv3)

