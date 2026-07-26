@echo off
echo Building Mahoraga Defense Engine for Windows...

where g++ >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] MinGW GCC compiler g++ was not found in PATH.
    echo Please ensure GCC is installed and added to your environment variables.
    exit /b 1
)

if not exist "..\src\mahoraga_latest.cpp" (
    cd /d "%~dp0"
)

echo Compiling mahoraga_latest.cpp (monolithic)...

g++ -std=c++20 -O2 -Wall ^
    -I"C:\npcap-sdk\Include" -L"C:\npcap-sdk\Lib\x64" ^
    ..\src\mahoraga_latest.cpp ^
    -o mahoraga.exe ^
    -march=native -static-libgcc -static-libstdc++ -lwpcap -lws2_32

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Compilation finished: mahoraga.exe
) else (
    echo [ERROR] Compilation failed. Ensure Npcap SDK and libwpcap are available.
)
