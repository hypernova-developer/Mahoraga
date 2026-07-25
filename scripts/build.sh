#!/bin/bash

echo "Building Mahoraga Defense Engine for Linux..."

if ! command -v g++ &> /dev/null; then
    echo "[ERROR] GCC compiler (g++) is not installed."
    echo "Install with: sudo apt install g++ libpcap-dev"
    exit 1
fi

if ! pkg-config --exists libpcap 2>/dev/null; then
    echo "[WARNING] libpcap not found via pkg-config. Ensure libpcap-dev is installed."
    echo "Install with: sudo apt install libpcap-dev"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "Choose build mode:"
echo "1) Monolithic (single file - mahoraga_latest.cpp)"
echo "2) Modular (multi-file from src/)"
read -p "Enter 1 or 2 (default 1): " BUILD_MODE
if [ "$BUILD_MODE" = "2" ]; then
    BUILD_TYPE="modular"
else
    BUILD_TYPE="monolithic"
fi

echo "Compiling using GCC ($BUILD_TYPE mode)..."

if [ "$BUILD_TYPE" = "monolithic" ]; then
    g++ -std=c++20 -O2 -Wall \
        ../mahoraga_latest.cpp \
        -o mahoraga \
        $(pkg-config --cflags --libs libpcap 2>/dev/null || echo "-lpcap") \
        -pthread
else
    g++ -std=c++20 -O2 -Wall \
        -I../include \
        ../src/main.cpp \
        ../src/ConfigurationManager.cpp \
        ../src/PacketCapture.cpp \
        ../src/FrameParser.cpp \
        ../src/RogueAPDetector.cpp \
        ../src/DeauthDetector.cpp \
        ../src/TrafficAnalyzer.cpp \
        ../src/AlarmManager.cpp \
        ../src/Logger.cpp \
        ../src/DefenseEngine.cpp \
        -o mahoraga \
        $(pkg-config --cflags --libs libpcap 2>/dev/null || echo "-lpcap") \
        -pthread
fi

if [ $? -eq 0 ]; then
    echo "[SUCCESS] Compilation finished: ./mahoraga"
    chmod +x mahoraga
else
    echo "[ERROR] Compilation failed."
    exit 1
fi

