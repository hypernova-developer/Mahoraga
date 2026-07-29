#ifndef OUTPUT_FORMATTER_HPP
#define OUTPUT_FORMATTER_HPP

#include <string>

namespace mahoraga
{

class OutputFormatter
{
public:
    OutputFormatter()
    {
    }

    void logStatus(const std::string& message) const;
    void logError(const std::string& message) const;
    void logAnomaly(const std::string& cgroupPath, const std::string& reason, const std::string& mitigation) const;
};

}

#endif
