# Virtrust API 接口文档

本文档描述了 virtrust 库对外提供的主要 API 接口，这些接口主要用于虚拟机域管理，包括创建、启动、停止、迁移和查询等操作。

## 核心数据结构

### 连接上下文 (ConnCtx)
- **作用**：表示与 libvirt 的连接上下文
- **默认 URI**：`qemu:///session`
- **创建方式**：使用 `std::make_unique<ConnCtx>()` 创建，可通过 `SetUri()` 方法设置连接地址

### 返回值 (VirtrustRc)
所有 API 函数都返回 `VirtrustRc` 枚举类型的返回值：
- `OK = 0`：操作成功
- `ERROR = 1`：一般错误
- `CHECK_FAILED = 2`：检查失败
- `INCONSISTENT_RESOURCE = 3`：资源不一致

## API 接口详情

### 1. DomainCreate - 创建虚拟机

```cpp
VirtrustRc DomainCreate(const std::unique_ptr<ConnCtx> &conn, const std::vector<std::string> &args);
```

**参数说明**：
- `conn`：连接上下文，必须是有效的连接
- `args`：参数向量，参考 `virt-install --help` 的参数格式
  - `args[0]`：必须为 virt-install 的路径，如 `/usr/bin/virt-install`
  - 必须指定虚拟机名称字段
  - `--allow-store-measurements`：可选参数，允许更新 TSB 的度量值

**功能描述**：
创建一个新的虚拟机实例。该函数内部调用 virt-install 工具来创建虚拟机，并处理相关的 TSB 资源初始化。

**返回值**：
- 成功返回 `VirtrustRc::OK`
- 失败返回相应的错误码

**注意事项**：
- `ConnCtx` 类中 `uri` 的长度为 [1, 1024]；注意可同时设置此 uri 以及 `virt-install --connect uri`，此时 `virt-install` 的 `uri` 会覆盖前置设置。
- 名称字段（`--name`）是必须的
- 确保 virt-install 路径正确且可执行，默认的 virt-install 二进制路径为 /usr/bin/virt-install
- 支持所有 virt-install 的标准参数，args 中每个 string 最大长度为 1024，vector 支持最大 size 为 150

### 2. DomainDestroy - 停止虚拟机

```cpp
VirtrustRc DomainDestroy(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName, 
                         unsigned int flags, bool isOnlyTsb = false);
```

**参数说明**：
- `conn`：连接上下文
- `domainName`：虚拟机名称或 UUID
  - 当 `isOnlyTsb` 为 true 时，只更新 TSB 相关资源
  - 当 `isOnlyTsb` 为 true 时，使用 UUID 时将忽略 flags 入参
- `flags`：销毁标志，参考 `DomainDestroyFlags`（当前仅定义 `DOMAIN_DESTROY_NONE = 0`）
- `isOnlyTsb`：是否只更新 TSB 资源的标志
  - `true`：仅更新 TSB 资源，不执行实际的虚拟机销毁
  - `false`：执行完整的虚拟机销毁操作

**功能描述**：
停止指定的虚拟机。可选择是否只处理 TSB 资源或执行完整的销毁操作。

**注意事项**：
- 当使用 `--only-tsb/isOnlyTsb` 选项时，入参 `domainName` 应传入对应虚拟机的 `uuid`
- domainName 长度为 [1, 200]

### 3. DomainMigrate - 迁移虚拟机

将虚拟机迁移到其他主机。当前仅支持离线迁移，虚拟机在 running/shut-off 状态下，非共享存储需要用户手动复制磁盘文件，例如 qcow2 到目的端口，目标存在同名运行的虚拟机情况下不能迁移，可配置源虚拟机是否删除，重复迁移会覆盖目标端虚拟机。

```cpp
VirtrustRc DomainMigrate(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName,
                         const std::string &destUri, unsigned int flags = 0);
```

**参数说明**：
- `conn`：连接上下文
- `domainName`：虚拟机名称
- `destUri`：目标端地址，格式为 `<protocol>://<hostip>:<port>/<path>`
  - 示例：`qemu+tls://7.7.7.7:8080/system`
- `flags`：迁移标志
  - 默认为 0：不删除源端虚拟机
  - `MIGRATE_UNDEFINE_SOURCE`：迁移成功后取消定义源端虚拟机

**功能描述**：
将虚拟机从当前主机迁移到目标主机。支持安全的迁移过程，包括 TSB 资源的同步。

**返回值**：
- 成功返回 `VirtrustRc::OK`
- 失败返回相应的错误码

### 4. DomainStart - 启动虚拟机

```cpp
VirtrustRc DomainStart(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName, 
                       unsigned int flags, bool isOnlyTsb = false);
```

**参数说明**：
- `conn`：连接上下文
- `domainName`：虚拟机名称或 UUID
  - 当 `isOnlyTsb` 为 true 时，只更新 TSB 相关资源
  - 当 `isOnlyTsb` 为 true 时，使用 UUID 时将忽略 flags 入参
- `flags`：启动标志，参考 `DomainStartFlags`（当前仅定义 `DOMAIN_START_NONE = 0`）
- `isOnlyTsb`：是否只更新 TSB 资源的标志
  - `true`：仅更新 TSB 资源
  - `false`：执行完整的虚拟机启动操作

**功能描述**：
启动指定的虚拟机。可以选择仅处理 TSB 资源或执行完整的启动流程。

**注意事项**：
- 当使用 `--only-tsb/isOnlyTsb` 选项时，入参 `domainName` 应传入对应虚拟机的 `uuid`
- `domainName` 长度为 [1, 200]
- `desturi` 为目标端 uri，格式为 `<protocol>://<hostip>:<port>/<path>`，如 `qemu+tls://<destip>/system`


### 5. DomainUndefine - 删除虚拟机

```cpp
VirtrustRc DomainUndefine(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName, 
                          unsigned int flags = 0, bool isOnlyTsb = false);
```

**参数说明**：
- `conn`：连接上下文
- `domainName`：虚拟机名称或 UUID
  - 当 `isOnlyTsb` 为 true 时，只更新 TSB 相关资源
  - 当 `isOnlyTsb` 为 true 时，使用 UUID 时将忽略 flags 入参
- `flags`：删除标志
  - 默认为 0：适用于不产生 NVRAM 文件的情况
  - `DOMAIN_UNDEFINE_NVRAM`：删除 NVRAM 文件
  - `DOMAIN_UNDEFINE_KEEP_NVRAM`：保留 NVRAM 文件
  - 注意：`DOMAIN_UNDEFINE_NVRAM` 和 `DOMAIN_UNDEFINE_KEEP_NVRAM` 不能同时指定
- `isOnlyTsb`：是否只删除 TSB 资源
  - `true`：仅删除 TSB 资源
  - `false`：执行完整的虚拟机删除操作

**功能描述**：
删除虚拟机的定义。处理 NVRAM 文件和 TSB 资源的清理。

**注意事项**：
- domainName 长度为 [1, 200]
- 当使用 `--only-tsb/isOnlyTsb` 选项时，入参 `domainName` 应传入对应虚拟机的 `uuid`

### 6. DomainList - 展示虚拟机

```cpp
VirtrustRc DomainList(const std::unique_ptr<ConnCtx> &conn, unsigned int flags,
                      std::unordered_map<std::string, DomainInfo> &domainInfos, 
                      bool printErrToCli = false);
```

**参数说明**：
- `conn`：连接上下文
- `flags`：列表标志，可组合使用
  - `LIST_DOMAINS_ACTIVE`：列出活动的虚拟机
  - `LIST_DOMAINS_INACTIVE`：列出非活动的虚拟机
  - 示例：`LIST_DOMAINS_ACTIVE | LIST_DOMAINS_INACTIVE`
- `domainInfos`：输出参数，查询到的虚拟机信息映射表
  - 键：虚拟机名称
  - 值：`DomainInfo` 结构体
- `printErrToCli`：是否在命令行显示 TSB 和 libvirt 资源不一致的错误信息
  - `true`：显示错误信息（注意：libvirt 有但 TSB 没有的情况不会显示，但会有 warn 日志）
  - `false`：不显示错误信息

**DomainInfo 结构体**：
```cpp
struct DomainInfo {
    std::string domainName;        // 虚拟机名称
    unsigned char state;           // 运行状态，virDomainState 枚举值
    unsigned long maxMem;          // 最大允许内存（KB）
    unsigned long memory;          // 当前使用内存（KB）
    unsigned short nrVirtCpu;      // 虚拟 CPU 数量
    unsigned long long cpuTime;    // CPU 使用时间（纳秒）
};
```

**功能描述**：
查询并列出符合条件的虚拟机信息，同时检查 TSB 资源和 libvirt 资源的一致性。

**注意事项**：
- `ConnCtx` 类中 `uri` 的长度为 [1, 1024]
- 当使用 `--only-tsb/isOnlyTsb` 选项时，入参 `domainName` 应传入对应虚拟机的 `uuid`

## 使用示例

### 基本使用流程

```cpp
#include "virtrust/api/domain.h"

// 创建连接上下文
auto conn = std::make_unique<ConnCtx>();
conn->SetUri("qemu:///session");

// 创建虚拟机
std::vector<std::string> args = {
    "/usr/bin/virt-install",
    "--name", "test-vm",
    "--memory", "2048",
    "--vcpus", "2",
    "--disk", "path=/var/lib/libvirt/images/test-vm.qcow2,size=10",
    "--cdrom", "/path/to/install.iso",
    "--network", "network=default",
    "--allow-store-measurements"
};

auto result = DomainCreate(conn, args);
if (result != VirtrustRc::OK) {
    // 处理错误
}

// 启动虚拟机
result = DomainStart(conn, "test-vm", DOMAIN_START_NONE, false);

// 查询虚拟机信息
std::unordered_map<std::string, DomainInfo> domainInfos;
result = DomainList(conn, LIST_DOMAINS_ACTIVE, domainInfos, true);

// 停止虚拟机
result = DomainDestroy(conn, "test-vm", DOMAIN_DESTROY_NONE, false);

// 删除虚拟机
result = DomainUndefine(conn, "test-vm", 0, false);
```

## 错误处理

所有 API 函数都返回 `VirtrustRc` 枚举值，建议在调用后检查返回值：

```cpp
auto rc = DomainCreate(conn, args);
switch (rc) {
    case VirtrustRc::OK:
        // 操作成功
        break;
    case VirtrustRc::ERROR:
        // 一般错误
        break;
    case VirtrustRc::CHECK_FAILED:
        // 检查失败
        break;
    case VirtrustRc::INCONSISTENT_RESOURCE:
        // 资源不一致
        break;
    default:
        // 未知错误
        break;
}
```
