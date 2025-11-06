#ifndef LOG_ADAPT_H
#define LOG_ADAPT_H
#include <iostream>
#include <sstream>
#include <string>
#include <utility>

#include "spdlog/common.h"
#include "spdlog/spdlog.h"

#include "virtrust/api/defines.h"
namespace virtrust {
const int STDOUT_TYPE = 0;
const int FILE_TYPE = 0;

class LogAdapt {
public:
    LogAdapt(int logType, std::string path, int rotationFileSize, int rotationFileCount)
        : logType_(logType), rotationFileSize_(rotationFileSize), rotationFileCount_(rotationFileCount){};
    ~LogAdapt() = default;

    VirtrustRc Initialize();
    static void UnInitialize();

    static int GetLogLevel();
    inline void SetLogLevel(int logLevel)
    {
        if (logLevel < 0) {
            std::cerr << "logLevel is invalid. logLevel is" << logLevel << std::endl;
            return;
        }
        logLevel_ = logLevel;
    }
    [[nodiscard]] inline bool IsLogLevelEnabled(int nowLevel) const
    {
        return nowLevel >= logLevel_;
    }
    VirtrustRc Log(int level, const char *prefix, const char *message) const;

    static VirtrustRc CreateInstance(int &logType, int logLevel, const char *path, int rotationFileSize,
                                     int rotationFileCount);
    static VirtrustRc SetTmpLogger(int logType, std::string realPath, int rotationFileSize, int rotationFileCount,
                                   int logLevel);
    static std::unique_ptr<LogAdapt> gSpdLogger;
    std::shared_ptr<spdlog::logger> spdLogger;
    static void Flush();
    static int loglevel;
    static VirtrustRc ValidateParams(int logType, const char *path, int rotationFileSize, int rotationFileCount);
    static thread_local std::string gLastErrorMessage;

private:
    int logType_;
    int logLevel_{0};
    std::string filePath_;
    int rotationFileSize_;
    int rotationFileCount_;
};

} // namespace virtrust
#endif
