#include "OutputFormatter.hpp"
#include <iostream>

namespace mahoraga
{

void OutputFormatter::logStatus(const std::string& message) const
{
    std::cout << "[STATUS] " << message << std::endl;
}

void OutputFormatter::logError(const std::string& message) const
{
    std::cerr << "[ERROR] " << message << std::endl;
}

void OutputFormatter::logAnomaly(const std::string& cgroupPath, const std::string& reason, const std::string& mitigation) const
{
    std::cout << "[ALERT] abnormal activity detected in cgroup: " << cgroupPath
              << " | reason: " << reason
              << " | mitigation: " << mitigation << std::endl;
}

}
