# Virtrust项目技术分享

## 项目概述
背景：可信软件基代理(TSB-Agent) 部署于操作系统，在可信根的支撑下，建立可信终端设备的主动免疫防御体系，提升终端安全能力。
其实现自主可信计算（Initiative Trusted Computing）体系中系统层要素采集、基础通信、控制执行功能。是实现自主可信计算（Initiative Trusted Computing）的重要部件。

实现原理： 主要是通过静态度量来实现， 其原理是在系统关键静态时间点对核心组件进行完整性校验、配置合规检查和信任链构建，有效解决了终端设备在启动阶段、配置管理、补丁更新、
合规审计等场景下的可信性保障问题。它将安全防护从“被动检测”转向“主动免疫”，确保终端从“出生”（启动）到“运行”的全过程处于可信状态，显著提升终端的安全基线和抗攻击能力，
为构建主动免疫防御体系提供了底层支撑。

我们主要做的事情是： TSB-Agent在操作系统完全加载前（或早期启动阶段）对BIOS/UEFI、引导加载程序（GRUB/Bootmgr）、内核文件、关键驱动等进行静态度量。

**Virtrust** 是一个为 openEuler 24.03 LTS SP2 平台设计的可信安全启动（TSB）代理，提供**虚拟化可信计算模块（vTPCM）**支持，专注于虚拟机域管理和可信度量功能。

### 核心定位
- **可信虚拟化解决方案**：为虚拟化环境提供完整的可信计算基础设施
- **国产化技术栈**：基于国密SM3算法，支持中国密码标准
- **企业级可靠性**：华为技术背景，专注于生产环境的稳定性


## 系统架构

### 整体架构图
```
┌─────────────────────────────────────────────────────────────┐
│                    应用层                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │  virtrust-sh │  │  libvirtrustd│  │  第三方应用 │          │
│  │  命令行工具  │  │   守护进程   │  │    客户端   │            │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│                    API层                                    │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              virtrust API (domain.h)                    ││
│  │  创建 │ 启动 │ 停止 │ 迁移 │ 列表 │ 删除                    ││
│  └─────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────┤
│                    核心层                                    │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐   │
│  │ API  │ │ Base │ │Crypto│ │Link  │ │Utils │ │DlLib │   │
│  │ 模块 │ │ 模块 │ │ 模块 │ │ 模块 │ │ 模块 │ │ 模块 │   │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘   │
├─────────────────────────────────────────────────────────────┤
│                    TSB层                                    │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                TSB Agent (Mock/Real)                    │ │
│  │             vTPCM管理 + 信任链验证                         │ │
│  └─────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    硬件层                                    │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │
│  │   Libvirt   │ │   OpenSSL   │ │   Libbounds │         │
│  │   虚拟化     │ │   加密库     │ │  内存安全    │         │
│  └─────────────┘ └─────────────┘ └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

### 项目结构
```
TSB-agent/virtrust/
├── src/virtrust/              # 核心库 (C++17)
│   ├── api/                   # 对外API接口
│   ├── base/                  # 基础工具 (日志/异常/字符串)
│   ├── crypto/                # 国密SM3算法实现
│   ├── link/                  # gRPC通信和迁移
│   ├── utils/                 # 实用工具
│   └── dllib/                 # 动态库抽象层
├── src/virtrust-sh/           # 命令行工具
├── src/libvirtrustd/          # 守护进程
├── src/mock/                  # Mock TSB代理(开发用)
└── test/                     # 完整测试套件
```

---

## 核心功能特性

### 1. **可信虚拟机生命周期管理**
```cpp
// 完整的虚拟机管理API (src/virtrust/api/domain.h)
VirtrustRc DomainCreate(const std::unique_ptr<ConnCtx> &conn, const std::vector<std::string> &args);
VirtrustRc DomainStart(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName,
                       unsigned int flags, bool isOnlyTsb = false);
VirtrustRc DomainDestroy(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName,
                          unsigned int flags, bool isOnlyTsb = false);
VirtrustRc DomainMigrate(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName,
                         const std::string &destUri, unsigned int flags = MIGRATE_UNDEFINE_SOURCE);
VirtrustRc DomainUndefine(const std::unique_ptr<ConnCtx> &conn, const std::string &domainName,
                          unsigned int flags = 0, bool isOnlyTsb = false);
VirtrustRc DomainList(const std::unique_ptr<ConnCtx> &conn, unsigned int flags,
                      std::unordered_map<std::string, DomainInfo> &domainInfos, bool printErrToCli = false);
```

**特色功能：**
- 支持部分TSB资源操作 (`isOnlyTsb` 参数)
- 智能资源一致性检查
- 完整的错误处理机制

### 2. **安全迁移系统**
```proto
// gRPC迁移协议 (src/virtrust/link/proto/migrate.proto)
syntax = "proto3";

package virtrust.protos;

service MigrationService {
  // 1: 准备迁移
  rpc PrepareMigration (PrepareMigRequest) returns (PrepareMigReply) {}

  // 2: 交换公钥
  rpc ExchangePkAndReport(EXchangePkAndReportRequest) returns(EXchangePkAndReportReply) {}

  // 3: 开始迁移
  rpc StartMigration(StartMigRequest) returns(StartMigReply) {}

  // 4：迁移虚机密码资源
  rpc SendVRsourceData(VRsourceInfoRequest) returns(VRsourceInfoReply) {}

  // 5: 通知迁移结果
  rpc NotifyVRMigrateResult(MigrateResultRequest) returns (MigrateResultReply) {}

  // 6: 迁移请求
  rpc DomainMigrate(DomainMigraterRequest) returns (DomainMigraterReply) {}
}
```

**安全特性：**
-  **证书验证**：双向证书认证确保迁移安全
-  **加密传输**：TLS加密的gRPC通信
-  **完整性验证**：基于SM3的信任链验证
- **智能调度**：支持离线迁移，避免数据损坏

### 3. **国密算法支持**
```cpp
// SM3哈希算法实现 (src/virtrust/crypto/sm3.h)
class Sm3 {
public:
    Sm3();
    Sm3Rc Reset();
    Sm3Rc Update(std::string_view data);
    std::vector<uint8_t> CumulativeHash() const;

    static constexpr size_t DigestSize()
    {
        return DIGEST_SIZE;
    }

private:
    SmartEVP_MD md_;
    SmartEVP_MD_CTX context_;
    static constexpr size_t DIGEST_SIZE = 32;
    static constexpr size_t UPDATE_SIZE_LIMIT = 1024 * 1024 * 1024; // 1G
};

std::array<uint8_t, Sm3::DigestSize()> DoSm3(std::string_view data);
Sm3Rc DoSm3(std::string_view data, std::vector<uint8_t> &out);
```

**算法特性：**
-  **SM3哈希**：32位摘要，支持大文件处理(1GB限制)
-  **内存安全**：智能指针管理，防止内存泄漏
-  **高性能**：优化的openssl实现

### 4. **基础设施**
#### **高性能日志系统**
```cpp
// 定制化日志适配 (src/virtrust/base/custom_logger.h)
// 支持多种级别：DEBUG/INFO/WARN/ERROR
// 文件输出：/tmp/virtrust.log
```

## 技术栈与实现亮点

### **依赖管理**
```cmake
# 自动下载并构建依赖
include(deps/openssl)      # 加密库
include(deps/spdlog)       # 日志库
include(deps/gtest)        # 测试框架
include(deps/rapidjson)    # JSON解析
```

### **编译配置**
```bash
# 多种构建模式
cmake -DCMAKE_BUILD_TYPE=Debug      # 调试模式
cmake -DCMAKE_BUILD_TYPE=Coverage  # 覆盖率分析
cmake -DCMAKE_BUILD_TYPE=Asan      # 内存检测

# 开发vs生产
-DUSE_MOCK_TSB_AGENT=On   # 开发(默认)
-DUSE_MOCK_TSB_AGENT=Off  # 生产环境
```

### **项目产出物**
- **库文件**：`libvirtrust.so` (主共享库)
- **可执行文件**：`virtrust-sh` (命令行工具)、`libvirtrustd` (守护进程)
- **测试程序**：完整的单元测试套件
