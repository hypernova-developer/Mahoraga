#include "DefenseEngine.hpp"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <sys/types.h>
#include <signal.h>

namespace mahoraga
{

DefenseEngine::DefenseEngine(const std::string& rootPath, uint64_t maxMemory, int maxPids)
    : scanner_(std::make_unique<CgroupScanner>(rootPath))
    , formatter_(std::make_unique<OutputFormatter>())
{
    scanner_->setLimits(maxMemory, maxPids);
}

bool DefenseEngine::freezeCgroup(const std::string& path)
{
    std::string freezePath = (std::filesystem::path(path) / "cgroup.freeze").string();
    if (!std::filesystem::exists(freezePath))
    {
        formatter_->logError("cgroup.freeze file does not exist for: " + path);
        return false;
    }
    std::ofstream file(freezePath);
    if (!file.is_open())
    {
        formatter_->logError("Failed to open cgroup.freeze for: " + path);
        return false;
    }
    file << "1";
    if (file.fail())
    {
        formatter_->logError("Failed to write to cgroup.freeze for: " + path);
        return false;
    }
    return true;
}

bool DefenseEngine::terminateProcesses(const std::vector<int>& pids)
{
    bool success = true;
    for (int pid : pids)
    {
        if (kill(static_cast<pid_t>(pid), SIGKILL) != 0)
        {
            formatter_->logError("Failed to kill process: " + std::to_string(pid));
            success = false;
        }
    }
    return success;
}

void DefenseEngine::scanAndDefend()
{
    formatter_->logStatus("Starting cgroup scan cycle...");
    std::vector<CgroupAnomaly> anomalies = scanner_->scan();
    if (anomalies.empty())
    {
        formatter_->logStatus("Scan cycle completed. No anomalies detected.");
        return;
    }
    for (const auto& anomaly : anomalies)
    {
        std::string actionType;
        if (anomaly.type == AnomalyType::MemoryLeak || anomaly.type == AnomalyType::MemoryLimitExceeded)
        {
            actionType = "Freeze Cgroup";
            formatter_->logAnomaly(anomaly.path, anomaly.details, actionType);
            if (freezeCgroup(anomaly.path))
            {
                formatter_->logStatus("Successfully froze cgroup: " + anomaly.path);
            }
            else
            {
                formatter_->logError("Failed to freeze cgroup: " + anomaly.path);
            }
        }
        else if (anomaly.type == AnomalyType::PidLimitExceeded)
        {
            actionType = "Terminate Processes";
            formatter_->logAnomaly(anomaly.path, anomaly.details, actionType);
            if (terminateProcesses(anomaly.pids))
            {
                formatter_->logStatus("Successfully terminated processes in cgroup: " + anomaly.path);
            }
            else
            {
                formatter_->logError("Some processes could not be terminated in cgroup: " + anomaly.path);
            }
        }
    }
}

}
