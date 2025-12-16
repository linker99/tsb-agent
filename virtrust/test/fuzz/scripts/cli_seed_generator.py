#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

# 配置
OUTPUT_DIR = "../corpus/fuzz_cli"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# CLI命令测试用例 - 基于003-virtrust-sh.md文档
CLI_COMMANDS = [
    # 基本命令测试
    ["virtrust-sh", "create"],
    ["virtrust-sh", "start"],
    ["virtrust-sh", "destroy"],
    ["virtrust-sh", "undefine"],
    ["virtrust-sh", "list"],
    ["virtrust-sh", "migrate"],

    # help和version命令
    ["virtrust-sh", "-h"],
    ["virtrust-sh", "--help"],
    ["virtrust-sh", "-v"],
    ["virtrust-sh", "--version"],
    ["virtrust-sh", "create", "--help"],
    ["virtrust-sh", "start", "--help"],
    ["virtrust-sh", "destroy", "--help"],
    ["virtrust-sh", "undefine", "--help"],
    ["virtrust-sh", "list", "--help"],
    ["virtrust-sh", "migrate", "--help"],

    # 基本选项组合
    ["virtrust-sh", "-d", "list"],  # 调试模式
    ["virtrust-sh", "--debug", "list"],
    ["virtrust-sh", "-c", "qemu:///system", "list"],  # 自定义连接
    ["virtrust-sh", "--connect=qemu:///system", "list"],
    ["virtrust-sh", "-c", "qemu+tcp://localhost:16509/system", "list"],
    ["virtrust-sh", "-c", "qemu+tls://192.168.1.100:16509/system", "list"],
    ["virtrust-sh", "-d", "-c", "qemu:///session", "list"],  # 组合选项

    # create命令 - 完整参数测试，使用mock匹配的域名
    ["virtrust-sh", "create", "--name=test-domain-1"],
    ["virtrust-sh", "create", "--name", "test-domain-2"],
    ["virtrust-sh", "create", "--name=test-domain-1", "--memory=2048"],
    ["virtrust-sh", "create", "--name=another-shut-off-domain", "--memory", "4096"],
    ["virtrust-sh", "create", "--name=running-domain", "--memory=2048", "--vcpus=2"],
    ["virtrust-sh", "create", "--name=test-domain-1", "--memory", "2048", "--vcpus", "2"],
    ["virtrust-sh", "create", "--name=test-domain-2", "--memory=2048", "--vcpus=2", "--disk-size=10G"],
    ["virtrust-sh", "create", "--name=test-domain-1", "--memory=4096", "--vcpus=4", "--disk", "path=/tmp/test.qcow2,size=20"],
    ["virtrust-sh", "create", "--name=test-domain-2", "--memory=4096", "--vcpus=2", "--disk", "path=/var/lib/libvirt/images/test.qcow2,size=20", "--cdrom", "/tmp/ubuntu-22.04.iso"],
    ["virtrust-sh", "create", "--name=test-domain-1", "--memory=2048", "--vcpus=2", "--disk", "path=/var/lib/libvirt/images/test.qcow2,size=10", "--cdrom", "/path/to/install.iso", "--network", "network=default"],
    ["virtrust-sh", "create", "--name=test-domain-1", "--memory=8192", "--vcpus=4", "--disk", "path=/tmp/test.img,size=5", "--pxe"],
    ["virtrust-sh", "create", "--import", "--name=test-domain-1", "--ram=2048", "--vcpus=4"],
    ["virtrust-sh", "create", "--cdrom=/path/to/iso", "--name=running-domain", "--ram=8192"],
    ["virtrust-sh", "create", "--pxe", "--network=default"],

    # create命令 - --allow-store-measurements选项
    ["virtrust-sh", "create", "--name=test-domain-1", "--allow-store-measurements"],
    ["virtrust-sh", "create", "--name=test-domain-2", "--memory=1024", "--allow-store-measurements"],

    # create命令 - 长参数名测试
    ["virtrust-sh", "create", "--name=very-long-domain-name-12345678901234567890", "--memory=8192", "--vcpus=4"],
    ["virtrust-sh", "create", "--name=test-domain-with-special-chars_123", "--memory=1024"],

    # start命令
    ["virtrust-sh", "start", "test-domain-1"],
    ["virtrust-sh", "start", "test-domain-2"],
    ["virtrust-sh", "start", "12345678-1234-1234-1234-123456789001"],
    ["virtrust-sh", "start", "--only-tsb", "12345678-1234-1234-1234-123456789002"],
    ["virtrust-sh", "start", "--only-tsb", "test-domain-1"],  # 错误用法测试
    ["virtrust-sh", "-d", "start", "test-domain-1"],  # 调试模式
    ["virtrust-sh", "-c", "qemu:///system", "start", "test-domain-2"],

    # destroy命令
    ["virtrust-sh", "destroy", "test-domain-1"],
    ["virtrust-sh", "destroy", "test-domain-2"],
    ["virtrust-sh", "destroy", "12345678-1234-1234-1234-123456789001"],
    ["virtrust-sh", "destroy", "--only-tsb", "12345678-1234-1234-1234-123456789002"],
    ["virtrust-sh", "destroy", "--only-tsb", "test-domain-1"],  # 错误用法测试
    ["virtrust-sh", "-d", "destroy", "test-domain-2"],

    # undefine命令
    ["virtrust-sh", "undefine", "test-domain-1"],
    ["virtrust-sh", "undefine", "--nvram", "test-domain-2"],
    ["virtrust-sh", "undefine", "--keep-nvram", "another-shut-off-domain"],
    ["virtrust-sh", "undefine", "--only-tsb", "12345678-1234-1234-1234-123456789001"],
    ["virtrust-sh", "undefine", "--nvram", "--only-tsb", "12345678-1234-1234-1234-123456789002"],
    ["virtrust-sh", "-d", "undefine", "test-domain-1"],

    # list命令
    ["virtrust-sh", "list"],
    ["virtrust-sh", "list", "--all"],
    ["virtrust-sh", "list", "-a"],
    ["virtrust-sh", "-d", "list"],
    ["virtrust-sh", "-d", "list", "--all"],
    ["virtrust-sh", "-c", "qemu:///system", "list", "--all"],

    # migrate命令 - 使用与mock匹配的域名
    ["virtrust-sh", "migrate", "test-domain-1", "qemu+tls://192.168.1.100:16509/system"],
    ["virtrust-sh", "migrate", "test-domain-2", "qemu+tls://192.168.1.101:16509/system"],
    ["virtrust-sh", "migrate", "another-shut-off-domain", "qemu+tls://192.168.1.102:16509/system"],
    ["virtrust-sh", "migrate", "test-domain-1", "qemu+tls://dest-host.com/system"],
    ["virtrust-sh", "migrate", "--undefinesource", "test-domain-2", "qemu+tls://dest-host/system"],
    ["virtrust-sh", "migrate", "another-shut-off-domain", "qemu+tls://[2001:db8::1]:16509/system"],  # IPv6测试
    ["virtrust-sh", "-d", "migrate", "test-domain-1", "qemu+tls://192.168.1.100:16509/system"],
    ["virtrust-sh", "-c", "qemu:///system", "migrate", "test-domain-2", "qemu+tls://dest-host:16509/system"],

    # migrate错误测试用例
    ["virtrust-sh", "migrate", "running-domain", "qemu+tls://192.168.1.100:16509/system"],  # 运行中的域不能迁移
    ["virtrust-sh", "migrate", "test-domain-1", "qemu+tcp://192.168.1.100:16509/system"],  # 必须是qemu+tls://
    ["virtrust-sh", "migrate", "nonexistent-domain", "qemu+tls://192.168.1.100:16509/system"],  # 域不存在

    # 迁移命令 - 完整生命周期测试
    ["virtrust-sh", "create", "--name=test-domain-1", "--memory=1024", "--vcpus=1"],
    ["virtrust-sh", "migrate", "test-domain-1", "qemu+tls://dest-host:16509/system"],

    # 边界情况和错误测试
    ["virtrust-sh"],  # 只有程序名
    ["virtrust-sh", ""],  # 空命令
    ["virtrust-sh", "invalid-command"],
    ["virtrust-sh", "--invalid-option"],
    ["virtrust-sh", "-x"],  # 无效短选项
    ["virtrust-sh", "create", "--invalid-arg"],
    ["virtrust-sh", "migrate"],  # 缺少必需参数
    ["virtrust-sh", "start"],  # 缺少必需参数
    ["virtrust-sh", "destroy"],  # 缺少必需参数
    ["virtrust-sh", "undefine"],  # 缺少必需参数
    ["virtrust-sh", "start", ""],  # 空域名
    ["virtrust-sh", "create", "--name="],  # 空名称
    ["virtrust-sh", "create", "--memory=invalid"],  # 无效内存值
    ["virtrust-sh", "create", "--vcpus=invalid"],  # 无效CPU值
    ["virtrust-sh", "migrate", "invalid-domain", "qemu+tls://localhost:16509/system"],  # 无效域名
    ["virtrust-sh", "start", "nonexistent-domain"],  # 不存在的域名

    # 特殊字符测试
    ["virtrust-sh", "create", "--name=test\x00vm"],
    ["virtrust-sh", "create", "--name=中文域名"],
    ["virtrust-sh", "create", "--name=domain-with-特殊字符"],
    ["virtrust-sh", "start", "虚拟机名称"],
    ["virtrust-sh", "migrate", "test-vm", "qemu+tls://主机名:16509/system"],

    # 长参数测试
    ["virtrust-sh", "create", "--name=" + "a" * 200],  # 最大长度测试
    ["virtrust-sh", "create", "--name=" + "a" * 300],  # 超长测试
    ["virtrust-sh", "migrate", "test-vm", "qemu+tls://" + "a" * 100 + ".example.com:16509/system"],
    ["virtrust-sh", "create", "--memory=" + "9" * 10],  # 超大内存值

    # 复杂组合测试
    ["virtrust-sh", "-d", "-c", "qemu+tls://localhost:16509/system", "create", "--name=complex-test-vm", "--memory=4096", "--vcpus=4", "--disk", "path=/tmp/complex-test.qcow2,size=50", "--cdrom", "/tmp/test.iso", "--network", "network=default", "--graphics", "spice"],
    ["virtrust-sh", "-d", "list", "--all"],
    ["virtrust-sh", "-c", "qemu+tcp://192.168.1.100:16509/system", "migrate", "--undefinesource", "test-domain-1", "qemu+tls://192.168.1.101:16509/system"],

    # 完整生命周期测试序列
    ["virtrust-sh", "create", "--name=lifecycle-test", "--memory=2048", "--vcpus=2", "--disk", "path=/tmp/lifecycle.qcow2,size=10"],
    ["virtrust-sh", "start", "lifecycle-test"],
    ["virtrust-sh", "list"],
    ["virtrust-sh", "destroy", "lifecycle-test"],
    ["virtrust-sh", "undefine", "--nvram", "lifecycle-test"],

    # 性能测试用例 - 使用mock支持的域名
    ["virtrust-sh", "create", "--name=test-domain-1", "--memory=8192", "--vcpus=4", "--disk", "path=/tmp/perf-test.qcow2,size=100"],
    ["virtrust-sh", "list", "--all"],
    ["virtrust-sh", "migrate", "test-domain-1", "qemu+tls://high-perf-host:16509/system"],
]

def serialize_command(cmd_args):
    """将CLI命令序列化为二进制格式"""
    if not cmd_args:
        return b""

    argc = min(len(cmd_args), 65535)  # 限制为uint16最大值

    result = argc.to_bytes(2, byteorder='little')

    for arg in cmd_args:
        arg_bytes = arg.encode('utf-8')
        arg_len = min(len(arg_bytes), 255)  # 限制为uint8最大值

        result += bytes([arg_len])
        result += arg_bytes[:arg_len]

    return result

def main():
    idx = 0
    for cmd in CLI_COMMANDS:
        seed = serialize_command(cmd)

        out_path = os.path.join(OUTPUT_DIR, f"cli_{idx:04d}")
        with open(out_path, "wb") as f:
            f.write(seed)

        print(f"[+] Generated {out_path} (argc={len(cmd):2d}, len={len(seed):3d}b) {' '.join(cmd[:3])}{'...' if len(cmd) > 3 else ''}")
        idx += 1

    print(f"\nGenerated {len(CLI_COMMANDS)} CLI seed files in {OUTPUT_DIR}")
    print(f"Seed files cover: create, start, destroy, undefine, list, migrate commands with various options and edge cases")

if __name__ == "__main__":
    main()