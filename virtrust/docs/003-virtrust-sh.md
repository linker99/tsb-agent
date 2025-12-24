# Virtrust Shell (virtrust-sh) 用户手册

## 概述

Virtrust Shell (virtrust-sh) 是 virtrust 项目的命令行界面工具，为用户提供了交互式的虚拟机管理功能。它基于 virtrust API 库构建，支持虚拟机的完整生命周期管理操作。

- **虚拟机生命周期管理**：创建、启动、停止、迁移、查询和删除虚拟机定义

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
| `destroy` | 强制关闭（停止）虚拟机域 |
| `list` | 列出虚拟机信息 |
| `migrate` | 迁移虚拟机到其他主机 |
| `start` | 启动（先前定义的）非活动虚拟机域 |
| `undefine` | 删除虚拟机定义 |

## 详细命令说明

### 1. create - 创建虚拟机

创建新的虚拟机实例，基于 libvirt 的 virt-install 工具实现。

**基本语法**：
```bash
virtrust-sh create [virt-install 支持的参数...]
```

**选项说明**：
- `-h | --help`：显示帮助信息

**参数说明**：
- 必须包含虚拟机名称参数（使用 `--name` 指定）
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
```

### 2. start - 启动虚拟机

启动虚拟机实例。

**基本语法**：
```bash
virtrust-sh start [options] <domain_name>
```

**选项说明**：
- `-h | --help`：显示帮助信息
- `--only-tsb`：仅启动 TSB 资源，需要提供虚拟机的 UUID 作为 domain_name

**参数说明**：
- `domain_name`：要启动的虚拟机名称或 UUID（使用 `--only-tsb` 选项时必须使用 UUID）

**示例**：
```bash
# 启动虚拟机
virtrust-sh start test-vm

# 使用调试模式启动
virtrust-sh -d start test-vm

# 仅启动 TSB 资源
virtrust-sh start --only-tsb <vm-uuid>
```

### 3. destroy - 强制关闭（停止）虚拟机

强制关闭（停止）运行中的虚拟机。

**基本语法**：
```bash
virtrust-sh destroy [options] <domain_name>
```

**选项说明**：
- `-h | --help`：显示帮助信息
- `--only-tsb`：仅停止 TSB 资源，需要提供虚拟机的 UUID 作为 domain_name

**参数说明**：
- `domain_name`：要强制关闭（停止）的虚拟机名称或 UUID（使用 `--only-tsb` 选项时必须使用 UUID）

**示例**：
```bash
# 强制关闭（停止）虚拟机
virtrust-sh destroy test-vm

# 仅停止 TSB 资源
virtrust-sh destroy --only-tsb <vm-uuid>
```

### 4. undefine - 删除虚拟机定义

删除虚拟机定义，但不会删除磁盘镜像文件。

**基本语法**：
```bash
virtrust-sh undefine [options] <domain_name>
```

**选项说明**：
- `-h | --help`：显示帮助信息
- `--nvram`：删除 NVRAM 文件（与 `--keep-nvram` 互斥）
- `--keep-nvram`：保留 NVRAM 文件（与 `--nvram` 互斥）
- `--only-tsb`：仅删除 TSB 资源，需要提供虚拟机的 UUID 作为 domain_name

**参数说明**：
- `domain_name`：要删除定义的虚拟机名称或 UUID（使用 `--only-tsb` 选项时必须使用 UUID）

**示例**：
```bash
# 删除虚拟机定义
virtrust-sh undefine test-vm

# 删除虚拟机定义并删除 NVRAM 文件
virtrust-sh undefine --nvram test-vm

# 删除虚拟机定义但保留 NVRAM 文件
virtrust-sh undefine --keep-nvram test-vm

# 仅删除 TSB 资源
virtrust-sh undefine --only-tsb <vm-uuid>
```

### 5. migrate - 迁移虚拟机

将虚拟机迁移到其他主机。当前仅支持离线迁移，虚拟机在 shut-off 状态下，非共享存储需要用户手动复制磁盘镜像文件到目的节点的相同木木目录下目的主机节点，；可配置源虚拟机是否删除，不支持重复迁移（目的端已存在会迁移失败）。

**基本语法**：
```bash
virtrust-sh migrate <domain_name> <dest_uri>
```

**选项说明**：
- `-h | --help`：显示帮助信息

**参数说明**：
- `domain_name`：要迁移的虚拟机名称，长度为 [1, 200]
- `dest_uri`：目标主机 URI，格式为 `<protocol>://<host>/<path>`，如 `qemu+tls://7.7.7.7/system`

**示例**：
```bash
# 迁移到远程主机
virtrust-sh migrate test-vm qemu+ssl://192.168.1.100/system

# 使用 TLS 加密迁移
virtrust-sh migrate test-vm qemu+tls://192.168.1.100/system
```

### 6. list - 列出虚拟机信息

显示系统中虚拟机的状态和信息。

**基本语法**：
```bash
virtrust-sh list [options]
```

**选项说明**：
- `-h | --help`：显示帮助信息
- `-a | --all`：列出所有虚拟机（包括活动和非活动的虚拟机，默认只列出活动虚拟机）

**输出列说明**：
- `Id`：虚拟机 ID（非活动虚拟机显示 "-"）
- `Name`：虚拟机名称
- `State`：虚拟机状态（running、shut off）

**示例**：
```bash
# 列出所有活动虚拟机
virtrust-sh list

# 列出所有虚拟机（包括非活动的）
virtrust-sh list --all

# 使用调试模式列出虚拟机
virtrust-sh -d list

# 查看帮助信息
virtrust-sh list --help
```

**示例输出**：
```
   Id   Name                 State
-------------------------------
    1   test-vm-1           running
    2   test-vm-2           shut off
```

## 日志管理

virtrust-sh 会将详细的操作日志写入当前工作目录下的 `virtrust.log` 文件。

## 使用示例

完整虚拟机生命周期管理

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

# 4. 强制关闭虚拟机
virtrust-sh destroy demo-vm

# 5. 删除虚拟机定义
virtrust-sh undefine demo-vm
```

