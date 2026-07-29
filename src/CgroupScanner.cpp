#include "CgroupScanner.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

namespace mahoraga
{

CgroupScanner::CgroupScanner(const std::string& rootPath)
    : rootPath_(rootPath)
    , maxMemoryLimit_(524288000)
    , maxPidLimit_(100)
{
}

void CgroupScanner::setLimits(uint64_t maxMemory, int maxPids)
{
    maxMemoryLimit_ = maxMemory;
    maxPidLimit_ = maxPids;
}

bool CgroupScanner::checkMemoryLeak(const std::string& path, uint64_t currentMemory)
{
    auto& history = memoryHistory_[path];
    history.push_back(currentMemory);
    if (history.size() > 5)
    {
        history.erase(history.begin());
    }
    if (history.size() < 3)
    {
        return false;
    }
    bool strictlyIncreasing = true;
    for (size_t i = 1; i < history.size(); ++i)
    {
        if (history[i] <= history[i - 1])
        {
            strictlyIncreasing = false;
            break;
        }
    }
    return strictlyIncreasing;
}

std::vector<CgroupAnomaly> CgroupScanner::scan()
{
    std::vector<CgroupAnomaly> anomalies;
    if (!std::filesystem::exists(rootPath_))
    {
        return anomalies;
    }
    try
    {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(rootPath_, std::filesystem::directory_options::skip_permission_denied))
        {
            if (entry.is_directory())
            {
                std::string cgroupPath = entry.path().string();
                std::string memFilePath = (entry.path() / "memory.current").string();
                std::string procsFilePath = (entry.path() / "cgroup.procs").string();
                std::string pidsFilePath = (entry.path() / "pids.current").string();

                uint64_t memoryUsage = 0;
                if (std::filesystem::exists(memFilePath))
                {
                    std::ifstream memFile(memFilePath);
                    if (memFile.is_open())
                    {
                        memFile >> memoryUsage;
                    }
                }

                std::vector<int> pids;
                if (std::filesystem::exists(procsFilePath))
                {
                    std::ifstream procsFile(procsFilePath);
                    if (procsFile.is_open())
                    {
                        int pid;
                        while (procsFile >> pid)
                        {
                            pids.push_back(pid);
                        }
                    }
                }

                int taskCount = 0;
                if (std::filesystem::exists(pidsFilePath))
                {
                    std::ifstream pidsFile(pidsFilePath);
                    if (pidsFile.is_open())
                    {
                        pidsFile >> taskCount;
                    }
                }
                else
                {
                    taskCount = static_cast<int>(pids.size());
                }

                if (taskCount == 0 && memoryUsage == 0 && pids.empty())
                {
                    continue;
                }

                if (taskCount > maxPidLimit_)
                {
                    CgroupAnomaly anomaly;
                    anomaly.path = cgroupPath;
                    anomaly.type = AnomalyType::PidLimitExceeded;
                    anomaly.details = "Task count " + std::to_string(taskCount) + " exceeds limit " + std::to_string(maxPidLimit_);
                    anomaly.metricValue = taskCount;
                    anomaly.pids = pids;
                    anomalies.push_back(anomaly);
                }

                if (memoryUsage > maxMemoryLimit_)
                {
                    CgroupAnomaly anomaly;
                    anomaly.path = cgroupPath;
                    anomaly.type = AnomalyType::MemoryLimitExceeded;
                    anomaly.details = "Memory usage " + std::to_string(memoryUsage) + " bytes exceeds limit " + std::to_string(maxMemoryLimit_);
                    anomaly.metricValue = memoryUsage;
                    anomaly.pids = pids;
                    anomalies.push_back(anomaly);
                }
                else if (checkMemoryLeak(cgroupPath, memoryUsage))
                {
                    CgroupAnomaly anomaly;
                    anomaly.path = cgroupPath;
                    anomaly.type = AnomalyType::MemoryLeak;
                    anomaly.details = "Monotonic memory growth detected over last " + std::to_string(memoryHistory_[cgroupPath].size()) + " scans";
                    anomaly.metricValue = memoryUsage;
                    anomaly.pids = pids;
                    anomalies.push_back(anomaly);
                }
            }
        }
    }
    catch (const std::exception& e)
    {
    }
    return anomalies;
}

}
