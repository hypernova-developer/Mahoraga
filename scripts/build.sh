#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p ../bin

g++ -std=c++20 -O2 -Wall ../src/*.cpp -o ../bin/mahoraga -pthread

if [ $? -eq 0 ]; then
    chmod +x ../bin/mahoraga
    exit 0
else
    exit 1
fi
