#ifndef CGROUP_SCANNER_HPP
#define CGROUP_SCANNER_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace mahoraga
{

enum class AnomalyType
{
    None,
    MemoryLeak,
    MemoryLimitExceeded,
    PidLimitExceeded
};

struct CgroupAnomaly
{
    std::string path;
    AnomalyType type;
    std::string details;
    uint64_t metricValue;
    std::vector<int> pids;
};

class CgroupScanner
{
public:
    CgroupScanner(const std::string& rootPath);

    void setLimits(uint64_t maxMemory, int maxPids);
    std::vector<CgroupAnomaly> scan();

private:
    std::string rootPath_;
    uint64_t maxMemoryLimit_;
    int maxPidLimit_;
    std::unordered_map<std::string, std::vector<uint64_t>> memoryHistory_;

    bool checkMemoryLeak(const std::string& path, uint64_t currentMemory);
};

}

#endif
