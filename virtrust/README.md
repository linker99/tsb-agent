# TSB-agent/virtrust

A Trusted Security Boot (TSB) Agent that provides virtualized Trusted Computing Module (vTPCM) support for openEuler 24.03 LTS SP3. This project enables trusted computing virtualization capabilities with a focus on virtual machine domain management and trust measurement.

## Project Overview

TSB-agent/virtrust is a sophisticated trusted computing solution for virtualized environments that implements:

- **Virtualized Trusted Computing Module (vTPCM)** management
- **Trust Chain Validation** for complete boot chain measurement and verification
- **Secure VM Migration** with encrypted certificate verification
- **Security Policy Management** for configurable security controls
- **Domain Management** for virtual machine lifecycle operations

The project is particularly focused on Chinese cryptographic standards (SM3) and openEuler integration, providing a comprehensive security architecture for virtualized environments.

## Architecture

### Project Structure

```
TSB-agent/virtrust/
├── cmake/                                    # 构建系统配置
│   ├── AddVirtrustTestIf.cmake               # 测试配置脚本
│   ├── ImportLibs.cmake                      # 库导入配置
│   └── SetToolchainFlags.cmake               # 工具链配置
├── docs/                                     # 项目文档
│   ├── 001-introduction.md                   # 项目介绍
│   ├── 002-virtrust-api.md                   # API文档
│   ├── 003-virtrust-sh.md                    # Shell接口文档
│   └── 004-virtrustd.md                      # 守护进程文档
├── src/                                      # 源代码目录
│   ├── libvirtrustd/                         # 守护进程库
│   │   ├── defines.h                         # 定义文件
│   │   ├── main.cpp                          # 主程序
│   │   ├── utils.cpp/.h                      # 工具函数
│   │   └── CMakeLists.txt                    # 构建配置
│   ├── tsb_agent/                            # TSB代理模块
│   │   ├── mock/                             # 模拟实现
│   │   │   ├── tsb_agent_adaptor.cpp         # 适配器实现
│   │   │   ├── tsb_agent_impl.cpp/.h         # 代理实现
│   │   │   ├── tsb_agent_impl_test.cpp       # 单元测试
│   │   │   ├── tsb_agent_test.cpp            # 代理测试
│   │   │   └── v_root.h                      # 虚拟根定义
│   │   ├── tsb_agent.h                       # 代理头文件
│   │   └── CMakeLists.txt                    # 构建配置
│   ├── virtrust/                             # 核心库实现
│   │   ├── api/                              # 公共API接口
│   │   │   ├── context.cpp/.h                # API上下文管理
│   │   │   ├── define_private.h              # 私有定义
│   │   │   ├── defines.h                     # 公共定义
│   │   │   ├── domain.cpp/.h                 # 虚拟机域生命周期操作
│   │   │   ├── domain_test.cpp               # 域操作测试
│   │   │   ├── file_lock.h                   # 文件锁实现
│   │   │   └── CMakeLists.txt                # 构建配置
│   │   ├── base/                             # 核心工具库
│   │   │   ├── custom_logger.cpp/.h          # 高性能日志系统
│   │   │   ├── custom_logger_test.cpp        # 日志测试
│   │   │   ├── exception.cpp/.h              # 异常处理框架
│   │   │   ├── exception_test.cpp            # 异常测试
│   │   │   ├── log_adapt.cpp/.h              # 日志适配层
│   │   │   ├── log_adapt_test.cpp            # 日志适配测试
│   │   │   ├── logger.h                      # 日志器定义
│   │   │   ├── str_utils.cpp/.h              # 字符串工具
│   │   │   ├── str_utils_test.cpp            # 字符串工具测试
│   │   │   └── CMakeLists.txt                # 构建配置
│   │   ├── crypto/                           # 加密算法实现
│   │   │   ├── sm3.cpp/.h                    # 国密SM3算法
│   │   │   ├── sm3_test.cpp                  # SM3算法测试
│   │   │   └── CMakeLists.txt                # 构建配置
│   │   ├── dllib/                            # 动态库加载抽象
│   │   │   ├── common.h                      # 公共定义
│   │   │   ├── libguestfs_defines.h          # libguestfs定义
│   │   │   ├── libguestfs.h                  # libguestfs接口
│   │   │   ├── libguestfs_test.cpp           # libguestfs测试
│   │   │   ├── libvirt_defines.h             # libvirt定义
│   │   │   ├── libvirt.h                     # libvirt接口
│   │   │   ├── libvirt_test.cpp              # libvirt测试
│   │   │   ├── libxml2_defines.h             # libxml2定义
│   │   │   ├── libxml2.h                     # libxml2接口
│   │   │   ├── libxml2_test.cpp              # libxml2测试
│   │   │   ├── openssl_defines.h             # OpenSSL定义
│   │   │   ├── openssl.h                     # OpenSSL接口
│   │   │   ├── openssl_test.cpp              # OpenSSL测试
│   │   │   ├── dllib_test.cpp                # 动态库测试
│   │   │   └── CMakeLists.txt                # 构建配置
│   │   ├── link/                             # 链接功能模块
│   │   │   ├── proto/                        # 协议定义
│   │   │   │   ├── migrate.grpc.pb.cc/.h     # gRPC迁移协议
│   │   │   │   ├── migrate.pb.cc/.h          # 迁移协议
│   │   │   │   ├── migrate.proto             # 协议定义文件
│   │   │   │   └── proto_tools.h             # 协议工具
│   │   │   ├── grpc_client.cpp/.h            # gRPC客户端
│   │   │   ├── grpc_client_test.cpp          # gRPC客户端测试
│   │   │   ├── grpc_server.cpp/.h            # gRPC服务器
│   │   │   ├── grpc_server_test.cpp          # gRPC服务器测试
│   │   │   ├── link_config_builder.h         # 链接配置构建器
│   │   │   ├── link_test.cpp                 # 链接测试
│   │   │   ├── migration_service_impl.cpp/.h # 迁移服务实现
│   │   │   ├── migration_service_impl_test.cpp # 迁移服务测试
│   │   │   ├── migration_session.cpp/.h      # 迁移会话管理
│   │   │   ├── migration_session_test.cpp    # 迁移会话测试
│   │   │   ├── proto_tools_test.cpp          # 协议工具测试
│   │   │   ├── defines.h                     # 链接模块定义
│   │   │   └── CMakeLists.txt                # 构建配置
│   │   ├── utils/                            # 工具函数模块
│   │   │   ├── async_timer.h                 # 异步定时器
│   │   │   ├── async_timer_test.cpp          # 异步定时器测试
│   │   │   ├── enum_check.h                  # 枚举检查工具
│   │   │   ├── file_io.cpp/.h                # 文件I/O操作
│   │   │   ├── file_io_test.cpp              # 文件I/O测试
│   │   │   ├── foreign_mounter.cpp/.h        # 外部文件系统挂载
│   │   │   ├── foreign_mounter_test.cpp      # 外部挂载测试
│   │   │   ├── migrate_helper.cpp/.h         # 迁移辅助工具
│   │   │   ├── migrate_helper_test.cpp       # 迁移辅助测试
│   │   │   ├── smart_deleter.h               # 智能删除器
│   │   │   ├── virt_xml_parser.cpp/.h        # 虚拟化XML解析器
│   │   │   ├── virt_xml_parser_test.cpp      # XML解析器测试
│   │   │   └── CMakeLists.txt                # 构建配置
│   │   └── CMakeLists.txt                    # 主构建配置
│   ├── virtrust-sh/                          # Shell接口
│   │   ├── operator/                         # 命令操作符
│   │   │   ├── op_create.cpp/.h              # 域创建操作
│   │   │   ├── op_create_test.cpp            # 创建操作测试
│   │   │   ├── op_destroy.cpp/.h             # 域销毁操作
│   │   │   ├── op_destroy_test.cpp           # 销毁操作测试
│   │   │   ├── op_itf.cpp/.h                 # 操作接口
│   │   │   ├── op_list.cpp/.h                # 域列表操作
│   │   │   ├── op_list_test.cpp              # 列表操作测试
│   │   │   ├── op_migrate.cpp/.h             # 域迁移操作
│   │   │   ├── op_migrate_test.cpp           # 迁移操作测试
│   │   │   ├── op_start.cpp/.h               # 域启动操作
│   │   │   ├── op_start_test.cpp             # 启动操作测试
│   │   │   ├── op_undefine.cpp/.h            # 域取消定义操作
│   │   │   ├── op_undefine_test.cpp          # 取消定义测试
│   │   │   ├── op_utils.h                    # 操作工具函数
│   │   │   └── CMakeLists.txt                # 构建配置
│   │   ├── defines.h                         # Shell定义
│   │   ├── main.cpp                          # 主程序入口
│   │   └── CMakeLists.txt                    # 构建配置
│   └── CMakeLists.txt                        # 主源码构建配置
├── test/                                     # 测试基础设施
│   ├── ca/                                   # 证书颁发机构
│   │   ├── cert.pem                          # CA证书
│   │   ├── cert.srl                          # 证书序列号
│   │   └── sk.pem                            # CA私钥
│   ├── client/                               # 客户端证书
│   │   ├── cert.pem                          # 客户端证书
│   │   ├── client.csr                        # 客户端证书签名请求
│   │   └── sk.pem                            # 客户端私钥
│   ├── data/                                 # 测试数据
│   │   ├── config.json                       # 配置文件
│   │   ├── grub.cfg                          # GRUB配置
│   │   ├── test.txt                          # 测试文本
│   │   └── test.xml                          # 测试XML
│   ├── server/                               # 服务器证书
│   │   ├── cert.pem                          # 服务器证书
│   │   ├── server.csr                        # 服务器证书签名请求
│   │   └── sk.pem                            # 服务器私钥
│   └── CMakeLists.txt                        # 测试构建配置
├── build.sh                                  # 构建脚本
├── CLAUDE.md                                 # Claude AI助手文档
├── CMakeLists.txt                            # 主构建配置
├── format-all.sh                             # 代码格式化脚本
├── README.md                                 # 项目说明文档
└── transcript.txt                            # 项目记录文档
```

### Core Components

## Building from Source

### Prerequisites

Supporting OS:
- openEuler 24.03 SP1
- openEuler 24.03 SP2

```bash
# c++ toolchain
sudo dnf install gcc g++ cmake make

# compile dependencies
sudo dnf install grpc grpc-devel grpc-plugins protobuf-devel protobuf-compiler
sudo dnf install libboundscheck-devel

# run-time dependencies
sudo dnf install libxml2-devel libguestfs-devel openssl-devel libvirt-devel
```

### Build Commands

```bash
# Clone the repository
git clone https://gitee.com/jamie-cui/TSB-agent.git
cd TSB-agent/virtrust

# Configure build (Release mode with tests)
cmake -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTING=ON

# Build all components
cmake --build build -- -j$(nproc)

# Run tests
cd build
ctest --output-on-failure

# Install (optional)
sudo cmake --install build
```

### Build Options

| Option | Description | Default |
|--------|-------------|---------|
| `CMAKE_BUILD_TYPE` | Build configuration (Debug/Release/RelWithDebInfo) | Release |
| `ENABLE_TESTING` | Enable unit tests | ON |
| `ENABLE_COVERAGE` | Enable code coverage reporting | OFF |

### Memory Safety

The project includes comprehensive bounds checking:

```bash
# Build with libboundscheck
cmake -B build -DENABLE_BOUNDS_CHECK=ON
cmake --build build

# Run with bounds checking
LD_LIBRARY_PATH=/path/to/libboundscheck ./build/bin/virtrust-sh
```

## Testing

### Unit Tests
```bash
# Run all tests
cd build
ctest

# Run specific test suite
./bin/custom_logger_test
./bin/domain_test
./bin/sm3_test
```

### Coverage Report
```bash
# Enable coverage
cmake -B build -DENABLE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest

# Generate coverage report
lcov --capture --directory build --output-file coverage.info
genhtml coverage.info --output-directory coverage_report
```

### Code Formatting
```bash
# Format all source code
./format-all.sh

# Or use clang-format directly
find src -name "*.cpp" -o -name "*.h" | xargs clang-format -i
```
