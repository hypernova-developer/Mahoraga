#ifndef DEFENSE_ENGINE_HPP
#define DEFENSE_ENGINE_HPP

#include "CgroupScanner.hpp"
#include "OutputFormatter.hpp"
#include <string>
#include <vector>
#include <memory>

namespace mahoraga
{

class DefenseEngine
{
public:
    DefenseEngine(const std::string& rootPath, uint64_t maxMemory, int maxPids);

    void scanAndDefend();

private:
    std::unique_ptr<CgroupScanner> scanner_;
    std::unique_ptr<OutputFormatter> formatter_;

    bool freezeCgroup(const std::string& path);
    bool terminateProcesses(const std::vector<int>& pids);
};

}

#endif
