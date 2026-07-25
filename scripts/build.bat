@echo off
echo Building Mahoraga Defense Engine for Windows...

where g++ >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] MinGW GCC compiler (g++) was not found in PATH.
    echo Please ensure GCC is installed and added to your environment variables.
    exit /b 1
)

if not exist "..\src\*.cpp" (
    cd /d "%~dp0"
)

echo.
echo Choose build mode:
echo 1) Monolithic (single file - mahoraga_latest.cpp)
echo 2) Modular (multi-file from src/)
set /p BUILD_MODE="Enter 1 or 2 (default 1): "
if "%BUILD_MODE%"=="2" (
    set BUILD_TYPE=modular
) else (
    set BUILD_TYPE=monolithic
)

echo Compiling using GCC (%BUILD_TYPE% mode)...

if "%BUILD_TYPE%"=="monolithic" (
    g++ -std=c++20 -O2 -Wall ^
        ..\mahoraga_latest.cpp ^
        -o mahoraga.exe ^
        -march=native -static-libgcc -static-libstdc++ -lwpcap -lws2_32
) else (
    g++ -std=c++20 -O2 -Wall -I..\include ^
        ..\src\main.cpp ^
        ..\src\ConfigurationManager.cpp ^
        ..\src\PacketCapture.cpp ^
        ..\src\FrameParser.cpp ^
        ..\src\RogueAPDetector.cpp ^
        ..\src\DeauthDetector.cpp ^
        ..\src\TrafficAnalyzer.cpp ^
        ..\src\AlarmManager.cpp ^
        ..\src\Logger.cpp ^
        ..\src\DefenseEngine.cpp ^
        -o mahoraga.exe ^
        -march=native -static-libgcc -static-libstdc++ -lwpcap -lws2_32
)

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Compilation finished: mahoraga.exe
) else (
    echo [ERROR] Compilation failed. Ensure Npcap SDK and libwpcap are available.
)

