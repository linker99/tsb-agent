# 简介

virtrust 是一个为 openEuler 24.03 LTS SP3 平台设计的可信安全启动（TSB）代理，提供虚拟化可信计算模块（vTPCM）支持，专注于虚拟机域管理和可信度量功能。本仓库实现了完整的可信虚拟机生命周期管理、安全迁移以及相关工具链。

## 项目概述

### 核心功能

- **可信虚拟机管理**：提供虚拟机完整的生命周期管理，包括创建、启动、停止、销毁和迁移操作
- **可信计算支持**：基于国密 SM3 算法的信任链验证，支持 vTPCM（虚拟化可信计算模块）管理
- **安全迁移**：支持虚拟机在不同主机间的安全迁移，具备证书验证和完整性检查
- **开发工具**：提供命令行工具 virtrust-sh和守护进程 libvirtrustd，方便用户操作和系统集成

## 环境要求

### 支持的操作系统
- openEuler 24.03 SP1
- openEuler 24.03 SP2

### 用户权限
命令行工具`virtrust-sh`和守护进程`libvirtrustd`都需以`root`权限运行。

### 编译依赖

```bash
# 基础编译工具
sudo dnf install gcc g++ cmake make

# 开发库
sudo dnf install grpc grpc-devel grpc-plugins protobuf-devel protobuf-compiler
sudo dnf install libboundscheck

# 运行时依赖
sudo dnf install libxml2-devel libguestfs-devel openssl-devel libvirt-devel

# 其他依赖（项目会自动下载）
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
