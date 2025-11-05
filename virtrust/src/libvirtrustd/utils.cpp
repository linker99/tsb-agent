/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>
#include <optional>

#include "libvirtrustd/defines.h"
#include "rapidjson/document.h"
#include "rapidjson/istreamwrapper.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "virtrust/link/link_config_builder.h"
#include "virtrust/utils/file_io.h"

namespace virtrust {

namespace {

constexpr uint32_t MAX_FILE_SIZE = 10 * 1024 * 1024; // 10* 1024 * 1024

std::optional<std::string> CanonicalPath(const std::string &path)
{
    if (path.empty() || path.size() > 4096L) {
        return std::nullopt;
    }

    /* It will callocate memory to store path*/
    std::array<char, PATH_MAX> resolvedPath;
    if (realpath(path.c_str(), resolvedPath.data()) == nullptr) {
        return std::nullopt;
    }
    return resolvedPath.data();
}

bool IsAbsolutePath(const std::string &filePath)
{
    if (filePath.length() == 0) {
        return false;
    }
    if (filePath[0] != '/') {
        return false;
    }
    if (strstr(filePath.c_str(), "/../") != nullptr || strstr(filePath.c_str(), "/./") != nullptr) {
        return false;
    }
    return true;
}

bool CheckFileAccess(const std::string &path, int mode)
{
    return access(path.c_str(), mode) != -1;
}

bool CheckFileStat(const std::string &filePath)
{
    struct stat st;
    if (stat(filePath.c_str(), &st) != 0) {
        return false;
    }

    if ((st.st_mode & S_IFMT) != S_IFREG || (st.st_size > MAX_FILE_SIZE)) {
        return false;
    }
    return true;
}

bool CheckConfigFile(const std::string &path)
{
    if (!IsAbsolutePath(path)) {
        VIRTRUST_LOG_ERROR("Got relatinve path.");
        return false;
    }
    if (!CheckFileStat(path)) {
        VIRTRUST_LOG_ERROR("Check path stat failed.");
        return false;
    }
    if (!CheckFileAccess(path, F_OK | R_OK)) {
        VIRTRUST_LOG_ERROR("File path access is not valid.");
        return false;
    }
    return true;
}

std::optional<rapidjson::Document> ReadJsonFile(const std::string &path)
{
    // canonical path
    auto realPath = CanonicalPath(path);
    if (!realPath) {
        VIRTRUST_LOG_ERROR("Canonical path failed.");
        return std::nullopt;
    }
    // check the validity of path
    if (!CheckConfigFile(realPath.value())) {
        VIRTRUST_LOG_ERROR("Read config error. File access check failed: {}", realPath.value());
        return std::nullopt;
    }

    // read path into ifstream
    std::ifstream file(realPath.value());
    if (!file.is_open()) {
        VIRTRUST_LOG_ERROR("Read config error. Cannot open file: {}", realPath.value());
        return std::nullopt;
    }

    // handle ifstream to rapidjson
    rapidjson::IStreamWrapper isw(file);
    rapidjson::Document doc;
    doc.ParseStream(isw);

    // in case of parse error
    if (doc.HasParseError()) {
        VIRTRUST_LOG_ERROR("Read config error. Cannto parse file into json: {}", realPath.value());
        return std::nullopt;
    }

    return doc;
}

template <typename T>
std::optional<T> FindJsonKey(const rapidjson::Document &jsonDoc, const std::string &key, T defaultValue)
{
    if (!jsonDoc.HasMember(key.data())) {
        VIRTRUST_LOG_WARN("ParseJsonDocToConfig: Failed to find config key:{}, Set it to default value.", key);
        return std::optional<T>(defaultValue);
    }

    const auto &value = jsonDoc[key.data()];
    if constexpr (std::is_same_v<T, std::string>) {
        return value.IsString() ? std::optional<T>(std::string(value.GetString())) : std::nullopt;
    } else if constexpr (std::is_same_v<T, uint16_t>) {
        return value.IsUint() ? std::optional<T>(value.GetUint()) : std::nullopt;
    } else {
        return std::nullopt;
    }
}

LinkConfig ParseJsonDocToConfig(const rapidjson::Document &jsonDoc)
{
    auto configBuidler = LinkConfigBuilder();

#define FIND_KEY(NAME, T, DEFAULT_VALUE)                          \
    do {                                                          \
        auto tmp = FindJsonKey<T>(jsonDoc, #NAME, DEFAULT_VALUE); \
        if (tmp) {                                                \
            configBuidler.NAME(tmp.value());                      \
        }                                                         \
    } while (0)

    FIND_KEY(caPath, std::string, std::string(LIBVIRTRUSTD_SERVER_ADDR));
    FIND_KEY(certPath, std::string, std::string(LIBVIRTRUSTD_CERT_PATH));
    FIND_KEY(skPath, std::string, std::string(LIBVIRTRUSTD_SK_PATH));
    FIND_KEY(ip, std::string, std::string(LIBVIRTRUSTD_SERVER_ADDR));
    FIND_KEY(ipMask, std::string, std::string(LIBVIRTRUSTD_SERVER_ADDR_MASK));
    FIND_KEY(port, uint16_t, LIBVIRTRUSTD_SERVER_PORT);

#undef FIND_KEY
    return configBuidler.Build();
}

} // namespace

std::optional<LinkConfig> MakeLinkConfigFromJsonFile(const std::string &configPath)
{
    auto jsonDoc = ReadJsonFile(configPath);
    if (!jsonDoc.has_value() || jsonDoc.value().IsNull()) {
        return std::nullopt;
    }
    return ParseJsonDocToConfig(jsonDoc.value());
}
} // namespace virtrust
