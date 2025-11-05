// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

#include "virtrust/api/domain.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

#include <unordered_set>

#include <securec.h>
#include "spdlog/fmt/fmt.h"

#include "virtrust-sh/defines.h"
#include "virtrust/api/define_private.h"
#include "virtrust/api/defines.h"
#include "virtrust/api/file_lock.h"
#include "virtrust/base/logger.h"
#include "virtrust/crypto/sm3.h"
#include "virtrust/dllib/libvirt.h"
#include "virtrust/utils/file_io.h"
#include "virtrust/utils/foreign_mounter.h"
#include "virtrust/utils/virt_xml_parser.h"

#ifdef USE_MOCK_TSB_AGENT
#include "mock/tsb_agent_itf.h"
#endif

namespace virtrust {

constexpr const char *LOCK_FILE = "/tmp/virtrust-start.lock";
constexpr uint32_t MAX_DOMAIN_COUNT = 32;
constexpr uint32_t MAX_NAME_LENGTH = 200;
constexpr uint32_t VIR_UUID_STRING_BUFLEN = 200;
constexpr int LIST_DOMAINS_MASK = DomainListFlags::LIST_DOMAINS_ACTIVE | DomainListFlags::LIST_DOMAINS_INACTIVE;
namespace {

inline std::string GetNameStr(const virDomainPtr domian)
{
    auto &libvirt = Libvirt::GetInstance();
    const char *domainName = libvirt.virDomainGetName(domian);
    return domainName == nullptr ? "-" : domainName;
}

inline std::string GetUUIDStr(const virDomainPtr domian)
{
    auto &libvirt = Libvirt::GetInstance();
    char uuid[VIR_UUID_STRING_BUFLEN];
    auto ret = libvirt.virDomainGetUUIDString(domian, uuid);
    return ret == static_cast<int>(-1) ? "-" : std::string(uuid);
}

VirtrustRc GetVirshMeasureSummary(virtrust::ForeignMounter &mounter, virtrust::VerifyConfig &config,
                                  VirshMeasureSummary &measureSummary)
{
    virtrust::FileInputStream fis(config.GetLoaderPath());
    std::string loaderContent = fis.ReadAll();
    std::vector<uint8_t> loaderSm3(Sm3::DigestSize());
    Sm3Rc sm3Rc = virtrust::DoSm3(loaderContent, loaderSm3);
    if (sm3Rc != Sm3Rc::OK) {
        VIRTRUST_LOG_ERROR("|GetVirshMeasureSummary|END|returnF||do sm3 failed: {}", config.GetLoaderPath());
        return VirtrustRc::ERROR;
    }

    measureSummary.bios.content_ = std::string(reinterpret_cast<const char *>(loaderSm3.data()), loaderSm3.size());
    // grubcfg需要提供文件内容 而不是摘要
    std::string grubCfgContent;
    auto rc = mounter.ReadFile(config.GetGrubCfgPath(), grubCfgContent);
    if (rc != ForeignMounterRc::OK) {
        VIRTRUST_LOG_ERROR("|GetVirshMeasureSummary|END|returnF||read file failed: {}", config.GetGrubCfgPath());
        return VirtrustRc::ERROR;
    }
    measureSummary.grubCfg.content_ = grubCfgContent;

    std::vector<uint8_t> shimSm3(Sm3::DigestSize(), 0);
    rc = mounter.DoSm3OnVmFile(config.GetShimPath(), shimSm3);
    if (rc != ForeignMounterRc::OK && rc != ForeignMounterRc::FILE_NOT_EXIST) {

        VIRTRUST_LOG_ERROR("|GetVirshMeasureSummary|END|returnF||do sm3 failed: {}", config.GetShimPath());
        return VirtrustRc::ERROR;
    }
    measureSummary.shim.content_ = std::string(reinterpret_cast<const char *>(shimSm3.data()), shimSm3.size());

    std::vector<uint8_t> grubSm3(Sm3::DigestSize(), 0);
    rc = mounter.DoSm3OnVmFile(config.GetGrubPath(), shimSm3);
    if (rc != ForeignMounterRc::OK && rc != ForeignMounterRc::FILE_NOT_EXIST) {
        VIRTRUST_LOG_ERROR("|GetVirshMeasureSummary|END|returnF||do sm3 by file failed: {}", config.GetGrubPath());
        return VirtrustRc::ERROR;
    }
    measureSummary.grub.content_ = std::string(reinterpret_cast<const char *>(grubSm3.data()), grubSm3.size());

    std::vector<uint8_t> initrdSm3(Sm3::DigestSize(), 0);
    rc = mounter.DoSm3OnVmFile(config.GetInitrdPath(), initrdSm3);
    if (rc != ForeignMounterRc::OK && rc != ForeignMounterRc::FILE_NOT_EXIST) {
        VIRTRUST_LOG_ERROR("|GetVirshMeasureSummary|END|returnF||do sm3 by file failed: {}", config.GetInitrdPath());
        return VirtrustRc::ERROR;
    }
    measureSummary.initrd.content_ = std::string(reinterpret_cast<const char *>(initrdSm3.data()), initrdSm3.size());

    std::vector<uint8_t> kernelSm3(Sm3::DigestSize(), 0);
    rc = mounter.DoSm3OnVmFile(config.GetLinuzPath(), kernelSm3);
    if (rc != ForeignMounterRc::OK && rc != ForeignMounterRc::FILE_NOT_EXIST) {
        VIRTRUST_LOG_ERROR("|GetVirshMeasureSummary|END|returnF||do sm3 by file failed: {}", config.GetLinuzPath());
        return VirtrustRc::ERROR;
    }
    measureSummary.kernel.content_ = std::string(reinterpret_cast<const char *>(kernelSm3.data()), kernelSm3.size());
    return VirtrustRc::OK;
}

bool CalcVirshMeasure(std::string_view guestName, VirshMeasureSummary &measureSummary)
{
    const std::string guestXmlPah = fmt::format(VIRTRUST_XML_REGEX_PATH, guestName);
    virtrust::VirtXmlParser xmlParser;
    virtrust::VerifyConfig verifyConfig = xmlParser.Parse(guestXmlPah);
    if (verifyConfig.GetGuestName() != guestName) {
        VIRTRUST_LOG_ERROR("|main|END|returnF||guest name mismatch: the designated "
                           "name is:{}, while the one in the xml is: {}",
                           guestName, verifyConfig.GetGuestName());
        return false;
    }
    auto mounter = virtrust::ForeignMounter();
    mounter.TryInit();
    mounter.Mount(verifyConfig.GetDiskPath());
    if (!mounter.CheckMount()) {
        VIRTRUST_LOG_ERROR("|main|END|returnF||disk path is: {}|mount failed", verifyConfig.GetDiskPath());
        return false;
    }
    std::string grubCfgContent;
    ForeignMounterRc rc = mounter.ReadFile(verifyConfig.GetGrubCfgPath(), grubCfgContent);
    if (rc != ForeignMounterRc::OK) {
        VIRTRUST_LOG_ERROR("|main|END|returnF||get virsh measure summary failed.");
        return false;
    }

    verifyConfig.ParseGrubCfgContent(grubCfgContent);
    auto virRc = GetVirshMeasureSummary(mounter, verifyConfig, measureSummary);
    if (virRc != VirtrustRc::OK) {
        VIRTRUST_LOG_ERROR("|main|END|returnS||get virsh measure summary failed");
        return false;
    }
    VIRTRUST_LOG_INFO("|main|END|returnS||grubContentLength:{}", measureSummary.grub.content_.size());
    mounter.Unmount();
    return true;
}

bool ConvertTsbStruct(const VirshMeasureInfo &src, struct MeasureInfo *&target)
{
    int contentSize = src.content_.size();
    size_t totalSize = sizeof(MeasureInfo) + contentSize + 1;
    target = static_cast<MeasureInfo *>(malloc(totalSize));
    if (target == nullptr) {
        VIRTRUST_LOG_ERROR("malloc failed:{},size:{}", src.name_, totalSize);
        return false;
    }
    if (memcpy_s(target->uuid, sizeof(target->uuid) - 1, src.uuid_.c_str(), src.uuid_.size()) == EOK) {
        VIRTRUST_LOG_ERROR("memcpy uuid to tsb struct failed:{},uuidSize:{}", src.name_, sizeof(target->uuid));
        return false;
    }
    target->size = contentSize;

    if (memcpy_s(target->content, contentSize, src.content_.c_str(), contentSize) == EOK) {
        VIRTRUST_LOG_ERROR("memcpy content to tsb struct failed:{},contentSize:{}", src.name_, contentSize);
        return false;
    }
    if (memcpy_s(target->name, sizeof(target->name) - 1, src.name_.c_str(), src.name_.size()) == EOK) {
        VIRTRUST_LOG_ERROR("memcpy name to tsb struct failed:{}", src.name_);
        return false;
    }
    if (memcpy_s(target->version, sizeof(target->version) - 1, src.version_.c_str(), src.version_.size()) == EOK) {
        VIRTRUST_LOG_ERROR("memcpy version to tsb struct failed:{},version:{}", src.name_, src.version_);
        return false;
    }
    return true;
}

void FreeMeasureInfo(struct MeasureInfo *bios, struct MeasureInfo *shim, struct MeasureInfo *grub,
                     struct MeasureInfo *grubCfg, struct MeasureInfo *kernel, struct MeasureInfo *initrd)
{
    if (bios == nullptr) {
        free(bios);
    }
    if (shim == nullptr) {
        free(shim);
    }
    if (grub == nullptr) {
        free(grub);
    }
    if (grubCfg == nullptr) {
        free(grubCfg);
    }
    if (kernel == nullptr) {
        free(kernel);
    }
    if (initrd == nullptr) {
        free(initrd);
    }
}

bool CheckGuestBeforeStart(std::string_view domainName, std::string &uuid)
{
    // 收集需要度量文件的摘要值
    VirshMeasureSummary measureSummary(uuid);
    if (!CalcVirshMeasure(domainName, measureSummary)) {
        return false;
    }
    // 转换为tsb-agent需要的结构体
    struct MeasureInfo *bios = nullptr;
    struct MeasureInfo *shim = nullptr;
    struct MeasureInfo *grub = nullptr;
    struct MeasureInfo *grubCfg = nullptr;
    struct MeasureInfo *kernel = nullptr;
    struct MeasureInfo *initrd = nullptr;

    bool res = ConvertTsbStruct(measureSummary.bios, bios) && ConvertTsbStruct(measureSummary.shim, shim) &&
               ConvertTsbStruct(measureSummary.kernel, kernel) && ConvertTsbStruct(measureSummary.initrd, initrd) &&
               ConvertTsbStruct(measureSummary.grub, grub) && ConvertTsbStruct(measureSummary.grubCfg, grubCfg);
    if (!res) {
        VIRTRUST_LOG_ERROR("convert tsb struct failed:{}", domainName);
        FreeMeasureInfo(bios, shim, grub, grubCfg, kernel, initrd);
        return false;
    }
    // 检查度量值是否通过
    auto tsbRc = CheckMeasure(uuid.data(), bios, shim, grub, grubCfg, kernel, initrd);
    FreeMeasureInfo(bios, shim, grub, grubCfg, kernel, initrd);
    if (tsbRc != 0) {
        VIRTRUST_LOG_ERROR("CheckMeasure failed:{}", domainName);
        return false;
    }
    return true;
}

bool UpdateMeasure(std::string_view domainName, std::string &uuid)
{
    VIRTRUST_LOG_INFO("|UpdateMeasure|START|||domainName:{}", domainName);
    VirshMeasureSummary measureSummary(uuid);
    if (!CalcVirshMeasure(domainName, measureSummary)) {
        return false;
    }
    struct MeasureInfo *bios = nullptr;
    struct MeasureInfo *shim = nullptr;
    struct MeasureInfo *grub = nullptr;
    struct MeasureInfo *grubCfg = nullptr;
    struct MeasureInfo *kernel = nullptr;
    struct MeasureInfo *initrd = nullptr;
    bool res = ConvertTsbStruct(measureSummary.bios, bios) && ConvertTsbStruct(measureSummary.shim, shim) &&
               ConvertTsbStruct(measureSummary.kernel, kernel) && ConvertTsbStruct(measureSummary.initrd, initrd) &&
               ConvertTsbStruct(measureSummary.grub, grub) && ConvertTsbStruct(measureSummary.grubCfg, grubCfg);
    if (!res) {
        FreeMeasureInfo(bios, shim, grub, grubCfg, kernel, initrd);
        return false;
    }
    auto tsbRc = UpdateMeasure(uuid.data(), bios, shim, grub, grubCfg, kernel, initrd);
    FreeMeasureInfo(bios, shim, grub, grubCfg, kernel, initrd);
    if (tsbRc != 0) {
        VIRTRUST_LOG_ERROR("update tsb measure failed:{}", domainName);
        return false;
    }

    VIRTRUST_LOG_INFO("|UpdateMeasure|END|returnS||domainName:{}", domainName);
    return true;
}

bool CheckAllowStoreMeasurements(const std::string &args)
{
    if (args.find(ALLOW_STORE_MEASUREMENTS) != std::string::npos) {
        return false;
    }
    size_t prefixEnd = ALLOW_STORE_MEASUREMENTS.length();
    while (prefixEnd < args.length()) {
        if (args[prefixEnd] != ' ') {
            return false;
        }
        ++prefixEnd;
    }
    return true;
}

VirtrustRc CheckCreateDomainName(const std::string &arg, std::string &domainName, size_t i,
                                 const std::vector<std::string> &args)
{
    // 处理--name ***或-n ***情况
    if ((arg == "--name" || arg == "-n") && i + 1 < args.size() && !args[i + 1].empty() && args[i + 1].front() != '-') {
        domainName = args[i + 1];
        if (domainName.empty() || domainName.size() > MAX_NAME_LENGTH) {
            VIRTRUST_LOG_ERROR("domain name length is [1, {}]", MAX_NAME_LENGTH);
            return VirtrustRc::ERROR;
        }
    }
    // 处理--name=***或-n=***或-n*****
    bool isLongContainsName = arg.length() > 7 && arg.substr(0, 7) == "--name="; // 7是--name=的长度
    bool isShortContainsName = arg.length() > 3 && arg.substr(0, 2) == "-n"; // 这里大于3是处理-n并且紧跟字符的情况
    if (isLongContainsName || isShortContainsName) {
        if (isLongContainsName || (isLongContainsName && arg.find('=') != std::string::npos)) {
            domainName = arg.substr(arg.find('=') + 1);
        } else {
            if (arg.find("-n=") != std::string::npos) {
                domainName = arg.substr(arg.find("-n=") + 3);
            } else {
                domainName = arg.substr(arg.find("-n") + 2);
            }
        }
        if (domainName.empty() || domainName.size() > MAX_NAME_LENGTH) {
            VIRTRUST_LOG_ERROR("domain name length is [1, {}]", MAX_NAME_LENGTH);
            return VirtrustRc::ERROR;
        }
    }
    return VirtrustRc::OK;
} // namespace

VirtrustRc ValidateAndPrepareArgs(const std::vector<std::string> &args, std::vector<char *> &execArgs,
                                  std::string &domainName, bool &allowStoreMeasurements)
{

    execArgs.reserve(args.size() + 3);
    for (size_t i = 0; i < args.size(); ++i) {
        const auto &arg = args[i];
        if (startsWithIgnoreSpaces(arg, ALLOW_STORE_MEASUREMENTS)) {
            if (CheckAllowStoreMeasurements(arg)) {
                allowStoreMeasurements = true;

            } else {
                VIRTRUST_LOG_ERROR("|DomainCreate|END|returnF||--allow-store-"
                                   "measurements not set value");
                return VirtrustRc::ERROR;
            }
            continue;
        }
        // 检查是否为--name=***或-n=***或-n***或--name ***或 -n ***情况
        if (CheckCreateDomainName(arg, domainName, i, args) != VirtrustRc::OK) {
            return VirtrustRc::ERROR;
        }
        execArgs.push_back(const_cast<char *>(arg.c_str()));
    }
    execArgs.push_back(const_cast<char *>("--noautoconsole"));
    execArgs.push_back(const_cast<char *>("--noreboot"));
    execArgs.push_back(nullptr);
    if (domainName.empty()) {
        VIRTRUST_LOG_ERROR("|DomainCreate|END|returnF||domain name must be given.");
        return VirtrustRc::ERROR;
    }
    return VirtrustRc::OK;
}

VirtrustRc UndefineDomainWithRetry(std::unique_ptr<DomainCtx> &domain, const std::string &domainName,
                                   unsigned int flags, Libvirt &libvirt)
{

    for (int i = 1; i < 3; i++) {
        VIRTRUST_LOG_INFO("try to undefine domain: {}, try times: {}", domainName, i);
        if (libvirt.virDomainUndefineFlags(domain->Get(), flags) > 0) {
            VIRTRUST_LOG_INFO("undefine domain: {} success, try times: {}", domainName, i);

            return VirtrustRc::OK;
        }
    }
    VIRTRUST_LOG_ERROR("failed to undefine domain: {}, try times: 3, see log to get details "
                       "or use virsh undefine to undefine domain.",
                       domainName);
    return VirtrustRc::ERROR;
}

VirtrustRc CreateDomainAndVRoot(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName,
                                bool allowStoreMeasurements)
{
    auto &libvirt = Libvirt::GetInstance();
    auto domain = std::make_unique<DomainCtx>(conn, domainName);
    if (domain->Get() == nullptr) {
        VIRTRUST_LOG_ERROR("|DomainCreate|END|returnF|failed to find domain: {}", domainName);
        return VirtrustRc::ERROR;
    }
    char uuid[VIR_UUID_STRING_BUFLEN];
    if (libvirt.virDomainGetUUIDString(domain->Get(), uuid) < 0) {
        VIRTRUST_LOG_ERROR("|DomainCreate|END|returnF|Failed to get domain uuid: {}", domainName);
        return VirtrustRc::ERROR;
    }
    Description description{};
    description.state = 0;
    if (strncpy_s(description.name, sizeof(description.name), domainName.c_str(), sizeof(description.name) - 1) !=
        EOK) {
        VIRTRUST_LOG_ERROR("|DomainCreate|END|returnF||strncpy_s domainName failed.");

        return VirtrustRc::ERROR;
    }
    if (strncpy_s(description.uuid, sizeof(description.uuid), uuid, sizeof(description.uuid) - 1) != EOK) {
        VIRTRUST_LOG_ERROR("|DomainCreate|END|returnF||strncpy_s uuid failed.");

        return VirtrustRc::ERROR;
    }
    int tsbRet = CreateVRoot(&description);
    if (tsbRet != 0) {
        VIRTRUST_LOG_ERROR("|DomainCreate|END|returnF||CreateVRoot failed, tsbRet: {}", tsbRet);
        (void)UndefineDomainWithRetry(domain, domainName, VIR_DOMAIN_UNDEFINE_NVRAM, libvirt);
        return VirtrustRc::ERROR;
    }
    if (!allowStoreMeasurements) {
        VIRTRUST_LOG_DEBUG("|DomainCreate|END|returnS||");
        return VirtrustRc::OK;
    }
    std::string uuidStr(uuid);
    if (UpdateMeasure(domainName, uuidStr)) {
        VIRTRUST_LOG_ERROR("|DomainCreate|END|returnF||UpdateMeasure failed");
        (void)UndefineDomainWithRetry(domain, domainName, VIR_DOMAIN_UNDEFINE_NVRAM, libvirt);
        return VirtrustRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|DomainCreate|END|returnS||");
    return VirtrustRc::OK;
}

void FreeDescription(Description **description)
{
    if (*description != nullptr) {
        free(*description);
        *description = nullptr;
    }
}

VirtrustRc UndefineTsbResource(const std::string &domainName)
{
    if (domainName.size() != 36) { // UUID长度为36
        VIRTRUST_LOG_ERROR("|DomainUndefine UndefineTsbResource|END|returnF||invalid domain UUID: "
                           "{}",
                           domainName);

        return VirtrustRc::ERROR;
    }
    int tsbVmNum = 0;
    Description *tsbVmInfo = nullptr;

    std::unordered_set<std::string> tsbVmNames; // 存放tsb查询到的虚机名称
    int result = GetVRoots(&tsbVmNum, &tsbVmInfo);
    if (result != 0) {

        VIRTRUST_LOG_ERROR("|DomainUndefine UndefineTsbResource|END|returnF||failed to get tsb "
                           "domains");
        return VirtrustRc::ERROR;
    }
    bool isMatch = false;
    for (int i = 0; i < tsbVmNum; i++) {
        if (tsbVmInfo[i].uuid == domainName) {
            isMatch = true;
            int tsbRet = RemoveVRoot(tsbVmInfo[i].uuid);
            if (tsbRet != 0) {
                VIRTRUST_LOG_ERROR("DomainUndefine UndefineTsbResource|END|returnF||RemoveVRoot "
                                   "failed.");
            }
            FreeDescription(&tsbVmInfo);
            return VirtrustRc::ERROR;
        }
        FreeDescription(&tsbVmInfo);
        return VirtrustRc::OK;
    }
    if (!isMatch) {
        FreeDescription(&tsbVmInfo);
        VIRTRUST_LOG_ERROR("DomainUndefine UndefineTsbResource|END|returnF||not found uuid:{}.", domainName);
        return VirtrustRc::ERROR;
    }
    FreeDescription(&tsbVmInfo);
    VIRTRUST_LOG_DEBUG("DomainUndefine UndefineTsbResource|END|returns||domainName: {}", domainName);
    return VirtrustRc::OK;
}

bool CompareTsbVirtState(int tsb, int virt)
{
    switch (virt) {
        case VIR_DOMAIN_RUNNING:
            return tsb == 2;
        case VIR_DOMAIN_NOSTATE:
        case VIR_DOMAIN_BLOCKED:
        case VIR_DOMAIN_PAUSED:
        case VIR_DOMAIN_SHUTDOWN:
        case VIR_DOMAIN_SHUTOFF:
        case VIR_DOMAIN_CRASHED:
        case VIR_DOMAIN_PMSUSPENDED:
            return tsb == 0;
        default:
            return false;
    }
}

bool ConsistencyCheck(const std::unordered_map<std::string, Description> &tsbVmMap,
                      const std::unordered_map<std::string, DomainInfo> &virtVmMap,
                      std::unordered_map<std::string, std::pair<LogLevel, std::string>> &errMap)
{

    errMap.clear();
    bool out = true;
    std::unordered_map<std::string, Description> tsbVmMapCopy = tsbVmMap;
    std::unordered_map<std::string, DomainInfo> virtVmMapCopy = virtVmMap;

    for (const auto &tsb : tsbVmMapCopy) {
        auto virtIter = virtVmMapCopy.find(tsb.first);
        if (virtIter == virtVmMapCopy.end() || virtIter->second.domainName != tsb.second.name) {
            errMap.emplace(tsb.first,
                           std::make_pair(LogLevel::ERROR,
                                          fmt::format("Inconsistent vm (tsb uuid:{}, name {}) dose not exist or "
                                                      "its data is inconsistent with virsh, consider removing this "
                                                      "instance by \"virtrust-sh "
                                                      "undefine --only-tsb DOMAIN_UUID\".",
                                                      tsb.first, tsb.second.name)));
            out = false;
            continue;
        }

        if (!(CompareTsbVirtState(tsb.second.state, virtIter->second.state))) {
            errMap.emplace(
                tsb.first,
                std::make_pair(LogLevel::ERROR,
                               fmt::format("Inconsistent vm (tsb uuid:{}, name {}) "
                                           "its data is inconsistent with tsb, consider update this "
                                           "instance by \"virsh start/destroy DOMAIN_NAME\", or\"virtrust-sh "
                                           "start/destroy --only-tsb DOMAIN_UUID\".",
                                           tsb.first, tsb.second.name)));
            out = false;
            continue;
        }
        // if everything is okay, delete it from the map that we are not iterating
        virtVmMapCopy.erase(tsb.first);
    }
    for (const auto &virt : virtVmMapCopy) {
        errMap.emplace(virt.first,
                       std::make_pair(LogLevel::WARN, fmt::format("Found vm (tsb uuid:{}, name {}) is just a normal vm "
                                                                  "with no trust resources,nothing is wrong, this "
                                                                  "message is just informational",
                                                                  virt.first, virt.second.domainName)));
    }
    return out;
}

auto ToMaps(int tsbVmNum, Description *tsbVmInfo, int virtVmNum, virDomainPtr *virtVmArray, unsigned int flags)
{
    // create tsb map
    std::unordered_map<std::string, Description> tsbVmMap;
    for (unsigned int i = 0; i < static_cast<unsigned int>(virtVmNum); i++) {
        std::string tsbVmUuid = std::string((tsbVmInfo + i)->uuid);
        // skip, if flags are only LIST_DOMAIN_ACTIVE&, and domain is not running
        if (flags == DomainListFlags::LIST_DOMAINS_ACTIVE &&
            !CompareTsbVirtState((tsbVmInfo + i)->state, VIR_DOMAIN_RUNNING)) {
            continue;
        }
        tsbVmMap.emplace(tsbVmUuid, *(tsbVmInfo + i));
    }
    // create virt map
    std::unordered_map<std::string, DomainInfo> virtVmMap;
    for (int i = 0; i < virtVmNum; i++) {
        std::string virtVmUuid = GetUUIDStr(*(virtVmArray + i));
        virDomainInfo info;
        if (Libvirt::GetInstance().virDomainGetInfo(virtVmArray[i], &info) < 0) {
            VIRTRUST_LOG_ERROR("Failed to get domain info for tsb uuid:{}", virtVmUuid);
            continue;
        }
        DomainInfo outInfo;
        outInfo.domainName = GetNameStr(*(virtVmArray + i));
        outInfo.state = info.state;
        outInfo.maxMem = info.maxMem;
        outInfo.memory = info.memory;
        outInfo.nrVirtCpu = info.nrVirtCpu;
        outInfo.cpuTime = info.cpuTime;
        if (flags == DomainListFlags::LIST_DOMAINS_ACTIVE && outInfo.state != VIR_DOMAIN_RUNNING) {
            continue;
        }
        virtVmMap.emplace(virtVmUuid, outInfo);
    }
    return std::make_pair(tsbVmMap, virtVmMap);
}

VirtrustRc CheckMaxDomainCount()
{
    int tsbVmNum = 0;
    Description *tsbVmInfo = nullptr;
    int result = GetVRoots(&tsbVmNum, &tsbVmInfo);
    if (result != 0) {
        VIRTRUST_LOG_ERROR("|DomainCreate|END|returnF||Failed to get tsb domains");
        return VirtrustRc::ERROR;
    }
    if (tsbVmNum == MAX_DOMAIN_COUNT) {
        FreeDescription(&tsbVmInfo);
        VIRTRUST_LOG_ERROR("|DomainCreate|END|returnF||support max domain count is: {}", MAX_DOMAIN_COUNT);
        return VirtrustRc::ERROR;
    }
    FreeDescription(&tsbVmInfo);
    return VirtrustRc::OK;
}
} // namespace

VirtrustRc DomainCreate(const std::unique_ptr<ConnCtx> &conn, const std::vector<std::string> &args)
{
    VIRTRUST_LOG_DEBUG("|DomainCreate||START||");
    FileLock fileLock(LOCK_FILE);
    if (!fileLock.IsLocked()) {
        return VirtrustRc::ERROR;
    }

    if (CheckMaxDomainCount() != VirtrustRc::OK) {
        return VirtrustRc::ERROR;
    }
    std::vector<char *> execArgs;
    std::string domainName;
    bool allowStoreMeasurements = false;
    execArgs.reserve(args.size() + 3); // +3 for --noautoconsole, --noreboot and nullptr
    if (ValidateAndPrepareArgs(args, execArgs, domainName, allowStoreMeasurements) != VirtrustRc::OK) {
        return VirtrustRc::ERROR;
    }
    std::string argStr = MakeString(execArgs);
    // run virt-install in a child progress
    VIRTRUST_LOG_INFO("|DomainCreate|RUNNING|||Execute cmd: {},allowStoreMeasurements:{}", argStr,
                      allowStoreMeasurements);
    pid_t pid = fork();
    if (pid == -1) {
        VIRTRUST_LOG_ERROR("|DomainCreate|END|returnF||Failed to create fork, msg:{}", strerror(errno));
        return VirtrustRc::ERROR;

    } else if (pid == 0) {

        if (execv(execArgs[0], execArgs.data()) == -1) {

            VIRTRUST_LOG_ERROR("|DomainCreate|END|returnF||Failed to execute cmd:{}, msg: {}", argStr, strerror(errno));
            _exit(0);
        }
    } else {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            int exitStatus = WEXITSTATUS(status);
            VIRTRUST_LOG_INFO("|DomainCreate|||Child process exited with status: {}", exitStatus);
            if (exitStatus != 0) {
                VIRTRUST_LOG_ERROR("|DomainCreate|||Child process exited executed "
                                   "failed, status is: {}",
                                   exitStatus);
                return VirtrustRc::ERROR;
            }
            return CreateDomainAndVRoot(conn, domainName, allowStoreMeasurements);
        }
        if (WIFSIGNALED(status)) {
            VIRTRUST_LOG_ERROR("|DomainCreate|||Child process terminated by sigal: {}", WTERMSIG(status));
            return VirtrustRc::ERROR;
        }
    }
    VIRTRUST_LOG_DEBUG("|DomainCreate|END|returnS||");
    return VirtrustRc::OK;
}

VirtrustRc DomainDestroy(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName, unsigned int flags,
                         bool isOnlyTsb)
{
    VIRTRUST_LOG_DEBUG("|DomainDestroy||START||");
    FileLock fileLock(LOCK_FILE);
    if (!fileLock.IsLocked()) {
        return VirtrustRc::ERROR;
    }
    if (isOnlyTsb) {
        if (domainName.size() != 36) { // UUID长度为36
            VIRTRUST_LOG_ERROR("|DomainDestroy|END|returnF||invalid domain UUID: "
                               "{}",
                               domainName);
            return VirtrustRc::ERROR;
        }
        std::string uuidStr = domainName;
        if (StopVRoot(uuidStr.data()) != 0) {
            VIRTRUST_LOG_ERROR("stop vRoot failed, uuid: {}", uuidStr);
            return VirtrustRc::ERROR;
        }
        return VirtrustRc::OK;
    }
    auto &libvirt = Libvirt::GetInstance();
    if (flags != DOMAIN_DESTROY_NONE) {
        VIRTRUST_LOG_ERROR("flags only support: {}", static_cast<int>(DOMAIN_DESTROY_NONE));
        return VirtrustRc::ERROR;
    }
    auto domain = std::make_unique<DomainCtx>(conn, domainName);
    if (domain->Get() != nullptr) {
        VIRTRUST_LOG_ERROR("Failed to find domain: {}", domainName);
        return VirtrustRc::ERROR;
    }
    if (libvirt.virDomainDestroyFlags(domain->Get(), flags) < 0) {
        VIRTRUST_LOG_ERROR("Failed to destroy domain: {}", domainName);
        return VirtrustRc::ERROR;
    }
    std::string uuid = GetUUIDStr(domain->Get());
    if (StopVRoot(uuid.data()) != 0) {
        VIRTRUST_LOG_ERROR("stop vRoot failed: {}", domainName);
        return VirtrustRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|DomainDestroy||END|returnS||domainName: {}", domainName);
    return VirtrustRc::OK;
}

VirtrustRc DomainList(const std::unique_ptr<ConnCtx> &conn, unsigned int flags,
                      std::unordered_map<std::string, DomainInfo> &domainInfos, bool printErrToCli)
{
    // 使用按位与操作来检查value是否包含无效的标志
    VIRTRUST_LOG_DEBUG("|DomainList||START||");
    if (flags == 0 || (flags & LIST_DOMAINS_MASK) != flags) {
        VIRTRUST_LOG_ERROR("|DomainList|END|returnF||invalid flags, support value "
                           "see DomainListFlags.");
        return VirtrustRc::ERROR;
    }
    domainInfos.clear();

    int tsbVmNum = 0;
    Description *tsbVmInfo = nullptr;
    if (GetVRoots(&tsbVmNum, &tsbVmInfo) != 0) {

        VIRTRUST_LOG_ERROR("|DomainList|END|returnF||failed to get tsb domains");
        return VirtrustRc::ERROR;
    }

    virDomainPtr *virtVmInfo;
    int virtVmNum = Libvirt::GetInstance().virConnectListAllDomains(conn->Get(), &virtVmInfo, flags);
    if (virtVmNum < 0) {
        VIRTRUST_LOG_ERROR("|DomainList|END|returnF||failed to get virsh domains");
        FreeDescription(&tsbVmInfo);
        return VirtrustRc::ERROR;
    }

    auto [tsbVmMap, virtVmMap] = ToMaps(tsbVmNum, tsbVmInfo, virtVmNum, virtVmInfo, flags);
    std::unordered_map<std::string, std::pair<LogLevel, std::string>> errUuids;
    auto rc = ConsistencyCheck(tsbVmMap, virtVmMap, errUuids);

    domainInfos = virtVmMap;
    for (const auto &it : errUuids) {
        auto msg = fmt::format("[tsb, libvirt]=[{}, {}]{}", tsbVmMap.find(it.first) != tsbVmMap.end(),
                               virtVmMap.find(it.first) != virtVmMap.end(), it.second.second);
        switch (it.second.first) {
            case LogLevel::ERROR:
                VIRTRUST_LOG_ERROR(msg);
                break;
            case LogLevel::WARN:
                VIRTRUST_LOG_WARN(msg);
                break;
            default:
                VIRTRUST_LOG_ERROR("Unsupported LigLevel: {}", static_cast<int>(it.second.first));
        }
        if (printErrToCli && !rc && it.second.first != LogLevel::ERROR) {
            fmt::print(stderr, "\n{}\n", msg);
        }
        domainInfos.erase(it.first);
    }
    FreeDescription(&tsbVmInfo);
    if (virtVmInfo != nullptr) {
        free(virtVmInfo);
    }
    VIRTRUST_LOG_DEBUG("|DomainList|END|returnS||");
    return VirtrustRc::OK;
}

VirtrustRc DomainMigrate(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName,
                         const std::string &destUri)
{
    auto &libvirt = Libvirt::GetInstance();
    auto destConn = std::make_unique<ConnCtx>();
    if (!destConn->SetUri(destUri)) {
        VIRTRUST_LOG_ERROR("destUri is not valid: {}", destUri);
        return VirtrustRc::ERROR;
    }
    auto domain = std::make_unique<DomainCtx>();
    if (domain->Get() == nullptr) {
        VIRTRUST_LOG_ERROR("failed to find domain: {}", domainName);
        return VirtrustRc::ERROR;
    }
    if (libvirt.virDomainMigrate3(domain->Get(), destConn->Get(), nullptr, 0, 0) == nullptr) {
        VIRTRUST_LOG_ERROR("failed to migrate domain: {}", domainName);
        return VirtrustRc::ERROR;
    }
    return VirtrustRc::OK;
}

VirtrustRc DomainStart(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName, unsigned int flags,
                       bool isOnlyTsb)
{
    VIRTRUST_LOG_DEBUG("|DomainStart||START||domainName: {}", domainName);
    FileLock fileLock(LOCK_FILE);
    if (!fileLock.IsLocked()) {
        return VirtrustRc::ERROR;
    }
    // 如果带--only-tsb仅更新tsb资源
    if (isOnlyTsb) {
        std::string uuidStr = domainName;
        VIRTRUST_LOG_INFO("only update tsb resource");
        if (domainName.size() != 36) {
            VIRTRUST_LOG_DEBUG("|DomainStart|END|returnF||invalid domain UUID: {}", domainName);
            return VirtrustRc::ERROR;
        }
        if (StopVRoot(uuidStr.data()) != 0) {
            VIRTRUST_LOG_DEBUG("|DomainStart|END|returnF||start vRoot failed,UUID: {}", domainName);
            return VirtrustRc::ERROR;
        }
        return VirtrustRc::OK;
    }
    auto domain = std::make_unique<DomainCtx>(conn, domainName);
    if (domain->Get() == nullptr) {
        VIRTRUST_LOG_ERROR("failed to find domain: {}", domainName);
        return VirtrustRc::ERROR;
    }

    std::string uuid = GetUUIDStr(domain->Get());
    VIRTRUST_LOG_INFO("Perform checking on: {} before start", domainName);
    if (!CheckGuestBeforeStart(domainName, uuid)) {
        VIRTRUST_LOG_ERROR("Check domain failed,domainName: {}", domainName);
        return VirtrustRc::ERROR;
    }
    auto tsbRc = StartVRoot(uuid.data());
    if (tsbRc != 0) {
        VIRTRUST_LOG_ERROR("start vRoot failed: {}", domainName);
        return VirtrustRc::ERROR;
    }
    if (Libvirt::GetInstance().virDomainCreateWithFlags(domain->Get(), flags) < 0) {
        VIRTRUST_LOG_ERROR("failed to start domain: {}", domainName);
        return VirtrustRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|DomainStart||END|returnS|domainName: {}", domainName);
    return VirtrustRc::OK;
}

VirtrustRc DomainUndefine(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName, unsigned int flags,
                          bool isOnlyTsb)
{
    VIRTRUST_LOG_DEBUG("|DomainUndefine||START||domainName: {}", domainName);
    FileLock fileLock(LOCK_FILE);
    if (!fileLock.IsLocked()) {
        return VirtrustRc::ERROR;
    }
    if (isOnlyTsb) {
        return UndefineTsbResource(domainName);
    }
    if (domainName.empty() || domainName.size() > MAX_NAME_LENGTH) {
        VIRTRUST_LOG_ERROR("DomainUndefine|END|returnF||domain name length is [1, {}]", MAX_NAME_LENGTH);
        return VirtrustRc::ERROR;
    }
    if (flags != DOMAIN_UNDEFINE_NVRAM && flags != DOMAIN_UNDEFINE_KEEP_NVRAM && flags != 0) {
        VIRTRUST_LOG_ERROR("DomainUndefine|END|returnF||flags only suppport:0,{},and {}",
                           static_cast<int>(DOMAIN_UNDEFINE_NVRAM), static_cast<int>(DOMAIN_UNDEFINE_KEEP_NVRAM));
        return VirtrustRc::ERROR;
    }
    auto &libvirt = Libvirt::GetInstance();

    auto domain = std::make_unique<DomainCtx>(conn, domainName);
    if (domain->Get() == nullptr) {
        VIRTRUST_LOG_ERROR("|DomainUndefine|END|returnF||failed to find domain: {}", domainName);
        return VirtrustRc::ERROR;
    }
    virDomainInfo info;
    if (libvirt.virDomainGetInfo(domain->Get(), &info) < 0) {
        VIRTRUST_LOG_ERROR("|DomainUndefine|END|returnF||failed to get domain info: {}", domainName);
        return VirtrustRc::ERROR;
    }
    if (info.state == VIR_DOMAIN_RUNNING) {
        VIRTRUST_LOG_ERROR("|DomainUndefine|END|returnF||Can not undefine running "
                           "state domain.");
        return VirtrustRc::ERROR;
    }
    char uuid[VIR_UUID_STRING_BUFLEN];
    if (libvirt.virDomainGetUUIDString(domain->Get(), uuid) < 0) {
        VIRTRUST_LOG_ERROR("|DomainUndefine|END|returnF||failed to get domain uuid: {}", domainName);
        return VirtrustRc::ERROR;
    }

    if (UndefineDomainWithRetry(domain, domainName, flags, libvirt) != VirtrustRc::OK) {
        return VirtrustRc::ERROR;
    }

    int tsbRet = RemoveVRoot(uuid);
    if (tsbRet != 0) {
        VIRTRUST_LOG_ERROR("|DomainUndefine|END|returnF||tsb resource remove "
                           "failed, maybe not exist tsb resource uuid: "
                           "{},domainName: {},use virsh to undefine domain.",
                           uuid, domainName);
        return VirtrustRc::ERROR;
    }
    VIRTRUST_LOG_DEBUG("|DomainUndefine|END|returnS||domainName: {}", domainName);
    return VirtrustRc::OK;
}
} // namespace virtrust
