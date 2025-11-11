# Virtrust Shell (virtrust-sh) 用户手册

## 概述

Virtrust Shell (virtrust-sh) 是 virtrust 项目的命令行界面工具，为用户提供了交互式的虚拟机管理功能。它基于 virtrust API 库构建，支持虚拟机的完整生命周期管理操作。

## 功能特性

- **虚拟机生命周期管理**：创建、启动、停止、销毁、迁移和删除虚拟机
- **命令行接口**：支持单个命令执行和批量操作
- **日志记录**：详细的操作日志记录，便于问题排查和审计
- **灵活配置**：支持自定义 hypervisor 连接 URI
- **调试模式**：提供详细的调试信息输出

## 安装和使用

### 基本语法

```bash
virtrust-sh [options]... [<command_string>]
virtrust-sh [options]... <command> [args...]
```

### 命令行选项

| 选项 | 长选项 | 参数 | 描述 |
|------|--------|------|------|
| `-c` | `--connect=URI` | URI | 指定 hypervisor 连接 URI，默认为 `qemu:///session` |
| `-d` | `--debug` | 无 | 启用调试模式，显示详细日志 |
| `-h` | `--help` | 无 | 显示帮助信息 |
| `-v` | `--version` | 无 | 显示版本信息 |

### 支持的命令

| 命令 | 描述 |
|------|------|
| `create` | 创建虚拟机实例 |
| `destroy` | 销毁（停止）虚拟机域 |
| `list` | 列出虚拟机信息 |
| `migrate` | 迁移虚拟机到其他主机 |
| `start` | 启动（先前定义的）非活动虚拟机域 |
| `undefine` | 取消定义虚拟机域 |

## 详细命令说明

### 1. create - 创建虚拟机

创建新的虚拟机实例，基于 libvirt 的 virt-install 工具。

**基本语法**：
```bash
virtrust-sh create [virt-install 参数...]
```

**参数说明**：
- 所有参数将传递给 virt-install 工具
- 必须包含虚拟机名称参数
- 支持所有 virt-install 的标准参数

**示例**：
```bash
# 创建基础虚拟机
virtrust-sh create \
  --name test-vm \
  --memory 2048 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/test-vm.qcow2,size=10 \
  --cdrom /path/to/install.iso \
  --network network=default

# 使用自定义连接 URI
virtrust-sh -c qemu+tcp://host/system create \
  --name test-vm \
  --memory 1024 \
  --vcpus 1 \
  --disk path=/tmp/test.img,size=5
```

### 2. start - 启动虚拟机

启动之前定义的虚拟机实例。

**基本语法**：
```bash
virtrust-sh start <domain_name>
```

**参数说明**：
- `domain_name`：要启动的虚拟机名称

**示例**：
```bash
# 启动虚拟机
virtrust-sh start test-vm

# 使用调试模式启动
virtrust-sh -d start test-vm
```

### 3. destroy - 停止虚拟机

强制停止运行中的虚拟机。

**基本语法**：
```bash
virtrust-sh destroy <domain_name>
```

**参数说明**：
- `domain_name`：要停止的虚拟机名称

**示例**：
```bash
# 停止虚拟机
virtrust-sh destroy test-vm
```

### 4. undefine - 删除虚拟机定义

删除虚拟机的配置定义，但不会删除磁盘镜像文件。

**基本语法**：
```bash
virtrust-sh undefine <domain_name>
```

**参数说明**：
- `domain_name`：要删除定义的虚拟机名称

**示例**：
```bash
# 删除虚拟机定义
virtrust-sh undefine test-vm
```

### 5. migrate - 迁移虚拟机

将虚拟机迁移到其他主机。

**基本语法**：
```bash
virtrust-sh migrate <domain_name> <dest_uri> [flags]
```

**参数说明**：
- `domain_name`：要迁移的虚拟机名称
- `dest_uri`：目标主机 URI，格式为 `<protocol>://<host>:<port>/<path>`

**示例**：
```bash
# 迁移到远程主机
virtrust-sh migrate test-vm qemu+tls://192.168.1.100:16509/system

# 使用 TLS 加密迁移
virtrust-sh migrate test-vm qemu+tls://dest-host/system
```

### 6. list - 列出虚拟机信息

显示系统中虚拟机的状态和信息。

**基本语法**：
```bash
virtrust-sh list [options]
```

**示例**：
```bash
# 列出所有虚拟机
virtrust-sh list

# 使用调试模式列出虚拟机
virtrust-sh -d list
```

## 日志管理

### 日志文件位置

virtrust-sh 会将详细的操作日志写入当前工作目录下的 `virtrust.log` 文件。

### 日志级别

- **默认级别**：INFO
- **调试模式**：DEBUG（使用 `-d` 选项启用）

### 日志内容包括

- 操作命令和参数
- 执行结果和时间戳
- 错误信息和堆栈跟踪
- libvirt 库的详细错误信息

## 使用示例

### 完整虚拟机生命周期管理

```bash
# 1. 创建虚拟机
virtrust-sh create \
  --name demo-vm \
  --memory 4096 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/demo-vm.qcow2,size=20 \
  --cdrom /tmp/ubuntu-22.04.iso \
  --network network=default \
  --graphics spice

# 2. 启动虚拟机
virtrust-sh start demo-vm

# 3. 查看虚拟机状态
virtrust-sh list

# 4. 停止虚拟机
virtrust-sh destroy demo-vm

# 5. 删除虚拟机定义
virtrust-sh undefine demo-vm
```

### 批量操作脚本

```bash
#!/bin/bash

# 设置调试模式
DEBUG_FLAG="-d"

# 批量启动虚拟机
for vm in vm1 vm2 vm3; do
    echo "Starting $vm..."
    virtrust-sh $DEBUG_FLAG start $vm
done

# 批量列出虚拟机状态
echo "Virtual machine status:"
virtrust-sh $DEBUG_FLAG list
```

### 远程管理示例

```bash
# 连接到远程 libvirt 守护进程
REMOTE_URI="qemu+tcp://192.168.1.100/system"

# 在远程主机上创建虚拟机
virtrust-sh -c $REMOTE_URI create \
  --name remote-vm \
  --memory 2048 \
  --vcpus 2 \
  --disk path=/var/lib/libvirt/images/remote-vm.qcow2,size=10

# 迁移虚拟机到远程主机
virtrust-sh migrate local-vm qemu+tls://192.168.1.100/system
```

## 错误处理和故障排除

### 常见错误类型

1. **连接错误**：无法连接到 libvirt 守护进程
2. **权限错误**：当前用户没有足够的权限执行操作
3. **参数错误**：命令参数格式不正确或缺少必需参数
4. **资源错误**：系统资源不足（内存、磁盘空间等）
5. **依赖错误**：virt-install 或其他依赖工具不可用

### 故障排除步骤

1. **检查日志**：查看 `virtrust.log` 文件获取详细错误信息
2. **验证连接**：确认 libvirt 服务正在运行且可访问
3. **检查权限**：确保当前用户有权限执行虚拟机操作
4. **验证参数**：检查命令参数格式和完整性
5. **查看系统资源**：确认有足够的系统资源

### 调试技巧

```bash
# 启用详细调试信息
virtrust-sh -d start test-vm

# 使用不同的连接 URI 进行测试
virtrust-sh -c qemu:///system list

# 检查 libvirt 连接状态
virsh list --all
```

## 最佳实践

### 1. 命令规范

- 使用描述性的虚拟机名称
- 在脚本中添加适当的错误处理
- 记录重要操作的时间和结果

### 2. 资源管理

- 定期清理不再需要的虚拟机
- 监控系统资源使用情况
- 合理配置虚拟机规格

### 3. 安全考虑

- 限制 virtrust-sh 的执行权限
- 使用安全的连接方式（如 TLS）
- 定期审查操作日志

### 4. 备份策略

- 定期备份重要的虚拟机配置
- 在执行破坏性操作前创建快照
- 保留关键操作的历史记录

## 性能优化

### 1. 批量操作

对于多个虚拟机的操作，建议使用脚本进行批量处理，而不是逐个手动执行。

### 2. 连接复用

在同一会话中多次执行命令时，使用相同的连接 URI 可以减少连接开销。

### 3. 日志管理

定期清理或轮转日志文件，避免日志文件过大影响系统性能。

## 版本信息

- **当前版本**：1.0.0
- **默认 virt-install 路径**：`/usr/bin/virt-install`
- **默认日志文件名**：`virtrust.log`
- **最大命令字符串长度**：1024 字符

## 相关文档

- [Virtrust API 文档](002-virtrust-api.md)
- [Virtrustd 守护进程文档](004-virtrustd.md)
- [项目简介](001-introduction.md)