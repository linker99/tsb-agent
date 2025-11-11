# 简介

virtrust 是一个为 openEuler 24.03 LTS SP3 平台设计的可信安全启动（TSB）代理，提供虚拟化可信计算模块（vTPCM）支持，专注于虚拟机域管理和可信度量功能。本仓库实现了完整的可信虚拟机生命周期管理、安全迁移以及相关工具链。

## 项目概述

### 核心功能

- **可信虚拟机管理**：提供虚拟机完整的生命周期管理，包括创建、启动、停止、销毁和迁移操作
- **可信计算支持**：基于国密 SM3 算法的信任链验证，支持 vTPCM（虚拟化可信计算模块）管理
- **安全迁移**：支持虚拟机在不同主机间的安全迁移，具备证书验证和完整性检查
- **开发工具**：提供命令行工具和守护进程，方便用户操作和系统集成

### 技术架构

- **安全架构**：完整信任链验证（BIOS → bootloader → kernel → TSB）
- **密码学支持**：国密 SM3 哈希算法实现
- **网络通信**：基于 gRPC 的高性能通信框架
- **模块化设计**：清晰的分层架构，便于扩展和维护

## 项目结构

### 核心库模块 (`src/virtrust/`)

#### API 接口层 (`api/`)
- `domain.cpp/h` - 虚拟机生命周期管理 API
- `context.cpp/h` - 连接上下文管理
- `defines.h` - API 定义和错误码

#### 基础组件 (`base/`)
- `custom_logger.cpp/h` - 高性能日志系统
- `exception.cpp/h` - 异常处理框架
- `str_utils.cpp/h` - 字符串工具
- `log_adapt.cpp/h` - 日志适配层

#### 密码学实现 (`crypto/`)
- `sm3.cpp/h` - 国密 SM3 哈希算法实现

#### 动态库抽象 (`dllib/`)
- 对 libvirt、libguestfs、libxml2、OpenSSL 的统一封装

#### 工具组件 (`utils/`)
- `file_io.cpp/h` - 文件 I/O 操作
- `virt_xml_parser.cpp/h` - XML 配置解析
- `migrate_helper.cpp/h` - 虚拟机迁移辅助
- `foreign_mounter.cpp/h` - 外部文件系统挂载

#### 网络通信 (`link/`)
- `grpc_client.cpp/h` - gRPC 客户端
- `grpc_server.cpp/h` - gRPC 服务器
- `migration_service_impl.cpp/h` - 迁移服务实现

### 命令行工具 (`src/virtrust-sh/`)
- `main.cpp` - CLI 入口点
- `operator/` - 命令操作器（创建、启动、销毁、列出、迁移等）

### 守护进程 (`src/libvirtrustd/`)
- 主守护进程实现和工具函数

### TSB 代理 (`src/tsb_agent/`)
- TSB 代理接口定义和模拟实现

## 环境要求

### 支持的系统
- openEuler 24.03 SP1
- openEuler 24.03 SP2
- openEuler 24.03 SP3

### 编译依赖

```bash
# 基础编译工具
sudo dnf install gcc g++ cmake make

# 开发库
sudo dnf install grpc-devel protobuf-devel libboundscheck-devel

# 其他依赖（项目会自动下载）
# - OpenSSL（加密）
# - spdlog（日志）
# - gtest（测试框架）
# - rapidjson（JSON解析）
```

## 编译指南

### 使用 CMake 直接编译

```bash
# 创建构建目录
mkdir -p build && cd build

# 配置构建（Release 构建）
cmake ..

# 配置构建（指定构建类型）
cmake -DCMAKE_BUILD_TYPE=Debug ..          # 调试构建
cmake -DCMAKE_BUILD_TYPE=Coverage ..       # 覆盖率构建
cmake -DCMAKE_BUILD_TYPE=Asan ..           # 地址消毒构建

# 配置选项
cmake -DBUILD_TEST=On ..                   # 启用测试（默认开启）
cmake -DUSE_MOCK_TSB_AGENT=Off ..          # 生产构建（禁用模拟代理）

# 编译
cmake --build . -j$(nproc)

# 安装
make install
```

### 使用构建脚本

```bash
# 默认构建（Release，禁用测试）
./build.sh

# 指定构建目标
./build.sh cicd_default
```

## 单元测试

### 运行所有测试

```bash
cd build

# 运行所有测试
ctest --output-on-failure

# 生成覆盖率报告（需要 Coverage 构建）
make coverage
```

### 运行单个测试

```bash
cd build/bin

# 域管理测试
./domain_test

# 日志系统测试
./custom_logger_test

# SM3 算法测试
./sm3_test

# 其他模块测试
./str_utils_test
./exception_test
# ... 等等
```

### 测试覆盖范围

项目采用测试文件与源码文件同目录的结构，覆盖所有核心模块：

- **API 测试**：域管理、上下文操作
- **基础组件测试**：日志、异常、字符串工具
- **密码学测试**：SM3 算法正确性验证
- **动态库测试**：各依赖库集成测试
- **工具测试**：文件操作、XML 解析、迁移辅助
- **命令行测试**：各操作命令功能验证
- **TSB 代理测试**：代理接口和适配器测试

## 产出物

### 库文件

- **`libvirtrust.so`** - 主要共享库，提供所有核心功能
- **`libvirtrust.a`** - 静态库版本（可选）

### 可执行文件

- **`virtrust-sh`** - 命令行工具，用于管理虚拟机
- **`libvirtrustd`** - 守护进程，提供后台服务
- **`mock-tsb-agent`** - 模拟 TSB 代理（开发测试用）

### 测试可执行文件

在 `build/bin/` 目录下生成所有测试程序：

- `domain_test`
- `custom_logger_test`
- `sm3_test`
- `str_utils_test`
- `exception_test`
- 以及其他模块的测试程序

### 配置和运行时文件

- **日志文件**：`/tmp/virtrust.log`
- **gRPC 套接字**：`/tmp/grpc.sock`
- **覆盖率报告**：`build/coverage/index.html`（Coverage 构建）

## 开发指南

### 代码风格

项目使用自动化代码格式化：

```bash
# 格式化所有代码
./format-all.sh
```

- 使用 clang-format 格式化 C++ 代码
- 使用 cmake-format 格式化 CMake 文件
- 配置文件：`.clang-format`

### 开发模式 vs 生产模式

- **开发模式**（默认）：`USE_MOCK_TSB_AGENT=On`
  - 使用模拟 TSB 代理
  - 启用完整测试套件
  - 便于开发和调试

- **生产模式**：`USE_MOCK_TSB_AGENT=Off`
  - 使用真实 TSB 代理
  - 禁用测试以减小二进制体积
  - 用于生产环境部署

### 调试支持

- **Debug 构建**：包含调试信息，支持 gdb
- **Asan 构建**：启用地址消毒，检测内存错误
- **Coverage 构建**：生成代码覆盖率报告

## 安全注意事项

- 生产构建**必须**设置 `USE_MOCK_TSB_AGENT=Off`
- TSB 代理接口使用 malloc/free，注意内存管理
- 所有密码学操作都经过安全验证
- 完整的边界检查确保内存安全

## 许可证

版权所有 © 2021-2021 华为技术有限公司 版权所有
