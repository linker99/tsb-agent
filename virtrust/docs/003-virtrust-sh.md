# Virtrust Shell (virtrust-sh) 用户手册

## 概述

Virtrust Shell (virtrust-sh) 是 virtrust 项目的命令行界面工具，为用户提供了交互式的虚拟机管理功能。它基于 virtrust API 库构建，支持虚拟机的完整生命周期管理操作。

- **虚拟机生命周期管理**：创建、启动、停止、销毁、迁移和删除虚拟机

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

创建新的虚拟机实例，基于 libvirt 的 virt-install 工具实现。

**基本语法**：
```bash
virtrust-sh create [virt-install 支持的参数...]
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
  --cdrom /path/to/install.iso f
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
virtrust-sh migrate [option] <domain_name> <dest_uri> 
```

**参数说明**：
- `domain_name`：要迁移的虚拟机名称
- `dest_uri`：目标主机 URI，格式为 `<protocol>://<host>:<port>/<path>`
- `option`：-h 帮助信息，--undefinesource 删除源端虚拟机

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

virtrust-sh 会将详细的操作日志写入当前工作目录下的 `virtrust.log` 文件。

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

