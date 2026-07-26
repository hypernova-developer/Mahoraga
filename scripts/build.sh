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

echo "Compiling mahoraga_latest.cpp (monolithic)..."

g++ -std=c++20 -O2 -Wall \
    ../src/mahoraga_latest.cpp \
    -o mahoraga \
    $(pkg-config --cflags --libs libpcap 2>/dev/null || echo "-lpcap") \
    -pthread

if [ $? -eq 0 ]; then
    echo "[SUCCESS] Compilation finished: ./mahoraga"
    chmod +x mahoraga
else
    echo "[ERROR] Compilation failed."
    exit 1
fi

