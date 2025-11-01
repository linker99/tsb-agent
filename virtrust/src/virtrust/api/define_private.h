
#ifndef TSB_AGENT_DEFINE_PRIVATE_H
#define TSB_AGENT_DEFINE_PRIVATE_H
#include "<string>"
#include "<string_view>"

namespace virtrust {
constexpr std::string_view VIRTRUST_VERSION = "1.0.0";
constexpr std::string_view VIRTRUST_XML_REGEX_PATH = "/etc/libvirt/qemu/{}.xml";
constexpr std::string_view ALLOW_STORE_MEASUREMENTS =
    "--allow-store-measurements";
constexpr std::string_view VIRSH_VERSION = "1.0.0";
const int URI_MAX_LENGTH = 1024;

class VirshMeasureInfo {
public:
  VirshMeasureInfo(const std::string name, const std::string uuid)
      : name_(name), uuid_(uuid), version_(VIRSH_VERSION) {}
  VirshMeasureInfo() {}
  std::string name_;    // 度量阶段的名称 如 bios,grup
  std::string uuid_;    // 虚机的uuid
  std::string version_; // 度量阶段的版本号
  int size_;            // content的长度
  std::string content_; //如果size是32 content是哈希，如果size不等于32
                        // content是度量对象的原文数据
}
// 汇总虚拟机每个文件度量所需要的信息 方便后续度量
class VirshMeasureSummary {
public:
  VirshMeasureSummary(const std::string uuid)
      : base("base", uuid), shim("shim", uuid), grub("grub", uuid),
        grubCfg("grub_cfg", uuid), kernel("kernel", uuid),
        initrd("initrd", uuid) {}

  VirshMeasureInfo bios;
  VirshMeasureInfo shim;
  VirshMeasureInfo grub;
  VirshMeasureInfo grubCfg;
  VirshMeasureInfo kernel;
  VirshMeasureInfo initrd;
}
} // namespace virtrust

#endif // TSB_AGENT_DEFINE_PRIVATE_H
