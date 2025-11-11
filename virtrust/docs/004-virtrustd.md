# Virtrust Daemon (virtrustd) 管理手册

## 概述

Virtrust Daemon (virtrustd) 是 virtrust 项目的守护进程服务，提供基于 gRPC 的远程 API 服务。它作为后端服务运行，接受来自客户端的虚拟机管理请求，并通过 virtrust API 库执行相应的操作。

## 功能特性

- **gRPC 服务接口**：提供高性能的远程过程调用接口
- **守护进程模式**：以后台服务形式运行，支持信号处理
- **配置文件驱动**：通过 JSON 配置文件进行灵活配置
- **TLS 安全支持**：支持 TLS 加密通信和证书验证
- **日志记录**：详细的服务运行日志记录
- **信号处理**：优雅的服务启动和关闭

## 系统架构

### 服务组件

```
virtrustd 守护进程
├── gRPC Server          # gRPC 服务器
├── LinkConfig          # 链接配置管理
├── 信号处理器          # SIGINT, SIGTERM, SIGPIPE 处理
├── 日志系统            # 服务日志记录
└── virtrust API        # 虚拟机管理 API 调用
```

### 通信流程

```
客户端应用
    ↓ (gRPC/TLS)
virtrustd 守护进程
    ↓ (virtrust API)
libvirt 虚拟化层
```

## 安装和部署

### 系统要求

- **操作系统**：openEuler 24.03 LTS SP3 或兼容系统
- **权限**：需要足够的权限来管理虚拟机
- **依赖**：libvirt、gRPC 相关库

### 安装步骤

1. **编译安装**：
```bash
# 在 virtrust 项目目录下
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# 安装服务
sudo cmake --install build
```

2. **创建配置文件**：
```bash
sudo mkdir -p /etc/virtrust
sudo cp config-example.json /etc/virtrust/virtrustd.json
```

3. **创建日志目录**：
```bash
sudo mkdir -p /var/log
sudo touch /var/log/virtrustd.log
sudo chmod 644 /var/log/virtrustd.log
```

## 配置管理

### 基本语法

```bash
virtrustd --config <config_file> [options]
```

### 命令行选项

| 选项 | 长选项 | 参数 | 描述 |
|------|--------|------|------|
| 无 | `--config` | 文件路径 | 配置文件路径（必需） |
| `-d` | `--debug` | 无 | 启用调试模式 |
| 无 | `--help` | 无 | 显示帮助信息 |
| 无 | `--version` | 无 | 显示版本信息 |

### 配置文件格式

配置文件使用 JSON 格式，包含以下字段：

```json
{
  "server": {
    "addr": "127.0.0.1",
    "port": 5031,
    "uds_path": "/tmp/grpc.sock"
  },
  "tls": {
    "ca_path": "ca-cert.pem",
    "cert_path": "server-cert.pem",
    "key_path": "server-sk.pem"
  }
}
```

#### 配置字段说明

**server 部分**：
- `addr`：服务器监听地址，默认为 "127.0.0.1"
- `port`：服务器监听端口，默认为 5031
- `uds_path`：Unix Domain Socket 路径，默认为 "/tmp/grpc.sock"

**tls 部分**：
- `ca_path`：CA 证书文件路径，默认为 "ca-cert.pem"
- `cert_path`：服务器证书文件路径，默认为 "server-cert.pem"
- `key_path`：服务器私钥文件路径，默认为 "server-sk.pem"

### 示例配置文件

**基础配置 (basic.json)**：
```json
{
  "server": {
    "addr": "127.0.0.1",
    "port": 5031,
    "uds_path": "/tmp/grpc.sock"
  },
  "tls": {
    "ca_path": "/etc/virtrust/certs/ca-cert.pem",
    "cert_path": "/etc/virtrust/certs/server-cert.pem",
    "key_path": "/etc/virtrust/certs/server-sk.pem"
  }
}
```

**生产环境配置 (production.json)**：
```json
{
  "server": {
    "addr": "0.0.0.0",
    "port": 5031,
    "uds_path": "/var/run/virtrustd.sock"
  },
  "tls": {
    "ca_path": "/etc/ssl/certs/virtrust-ca.pem",
    "cert_path": "/etc/ssl/private/virtrust-server.pem",
    "key_path": "/etc/ssl/private/virtrust-server.key"
  }
}
```

## 运行和管理

### 启动服务

```bash
# 基础启动
sudo virtrustd --config /etc/virtrust/virtrustd.json

# 调试模式启动
sudo virtrustd --config /etc/virtrust/virtrustd.json --debug
```

### 系统服务配置

创建 systemd 服务文件 `/etc/systemd/system/virtrustd.service`：

```ini
[Unit]
Description=Virtrust Daemon
After=network.target libvirtd.service
Wants=libvirtd.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/virtrustd --config /etc/virtrust/virtrustd.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**服务管理命令**：
```bash
# 重新加载 systemd 配置
sudo systemctl daemon-reload

# 启动服务
sudo systemctl start virtrustd

# 停止服务
sudo systemctl stop virtrustd

# 重启服务
sudo systemctl restart virtrustd

# 查看服务状态
sudo systemctl status virtrustd

# 开机自启
sudo systemctl enable virtrustd

# 禁用开机自启
sudo systemctl disable virtrustd
```

### 服务状态监控

```bash
# 检查服务是否运行
sudo systemctl is-active virtrustd

# 查看服务日志
sudo journalctl -u virtrustd -f

# 查看最近的错误日志
sudo journalctl -u virtrustd --since "1 hour ago" -p err
```

## 日志管理

### 日志文件位置

- **日志文件**：`/var/log/virtrustd.log`
- **系统日志**：通过 systemd journal 记录

### 日志级别

- **默认级别**：INFO
- **调试模式**：DEBUG（使用 `--debug` 选项启用）

### 日志轮转配置

创建 logrotate 配置文件 `/etc/logrotate.d/virtrustd`：

```
/var/log/virtrustd.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        systemctl reload virtrustd
    endscript
}
```

## 安全配置

### TLS 证书管理

1. **生成 CA 证书**：
```bash
# 创建 CA 私钥
openssl genrsa -out ca-key.pem 4096

# 创建 CA 证书
openssl req -new -x509 -days 365 -key ca-key.pem -out ca-cert.pem \
  -subj "/C=CN/ST=State/L=City/O=Organization/CN=Virtrust-CA"
```

2. **生成服务器证书**：
```bash
# 生成服务器私钥
openssl genrsa -out server-key.pem 2048

# 生成证书签名请求
openssl req -new -key server-key.pem -out server-req.pem \
  -subj "/C=CN/ST=State/L=City/O=Organization/CN=virtrustd-server"

# 签发服务器证书
openssl x509 -req -days 365 -in server-req.pem -CA ca-cert.pem \
  -CAkey ca-key.pem -CAcreateserial -out server-cert.pem
```

3. **权限设置**：
```bash
# 设置证书文件权限
sudo chown root:root ca-cert.pem server-cert.pem server-key.pem
sudo chmod 644 ca-cert.pem server-cert.pem
sudo chmod 600 server-key.pem

# 移动到安全位置
sudo mv ca-cert.pem server-cert.pem server-key.pem /etc/virtrust/certs/
```

### 防火墙配置

```bash
# 开放 gRPC 服务端口
sudo firewall-cmd --permanent --add-port=5031/tcp
sudo firewall-cmd --reload
```

### 访问控制

1. **网络隔离**：使用防火墙规则限制访问源
2. **用户权限**：确保只有授权用户可以访问服务
3. **证书验证**：启用客户端证书验证

## 性能优化

### 连接池配置

```json
{
  "server": {
    "max_connections": 100,
    "connection_timeout": 30,
    "keepalive_timeout": 60
  }
}
```

### 资源限制

```bash
# 设置文件描述符限制
ulimit -n 65536

# 设置进程限制
systemd-run --property=LimitNOFILE=65536 virtrustd --config config.json
```

## 监控和维护

### 健康检查

```bash
# 检查服务端口
netstat -tlnp | grep 5031

# 检查进程状态
ps aux | grep virtrustd

# 检查 Unix Socket
ls -la /tmp/grpc.sock
```

### 性能监控

```bash
# CPU 和内存使用情况
top -p $(pgrep virtrustd)

# 网络连接状态
ss -tlnp | grep 5031

# 磁盘 I/O 情况
iotop -p $(pgrep virtrustd)
```

## 故障排除

### 常见问题

1. **服务启动失败**：
   - 检查配置文件语法
   - 验证证书文件路径和权限
   - 确认端口未被占用

2. **客户端连接失败**：
   - 检查网络连接
   - 验证 TLS 证书
   - 确认防火墙设置

3. **权限错误**：
   - 检查文件权限设置
   - 确认用户组成员关系
   - 验证 SELinux 策略

### 调试方法

1. **启用调试模式**：
```bash
sudo virtrustd --config /etc/virtrust/virtrustd.json --debug
```

2. **查看详细日志**：
```bash
sudo tail -f /var/log/virtrustd.log
sudo journalctl -u virtrustd -f
```

3. **连接测试**：
```bash
# 测试 TCP 连接
telnet localhost 5031

# 测试 Unix Socket
nc -U /tmp/grpc.sock
```

## API 接口

virtrustd 提供 gRPC API 接口，具体接口定义请参考：
- Proto 文件：`proto/virtrust.proto`
- API 文档：[Virtrust API 文档](002-virtrust-api.md)

### 客户端示例

```python
import grpc
import virtrust_pb2
import virtrust_pb2_grpc

# 创建 gRPC 连接
channel = grpc.insecure_channel('localhost:5031')
stub = virtrust_pb2_grpc.VirtrustServiceStub(channel)

# 调用 API
request = virtrust_pb2.DomainListRequest()
response = stub.DomainList(request)
```

## 版本信息

- **当前版本**：1.0.0
- **默认服务器地址**：127.0.0.1
- **默认服务器端口**：5031
- **默认 Unix Socket**：/tmp/grpc.sock
- **默认日志文件**：/var/log/virtrustd.log

## 相关文档

- [Virtrust API 文档](002-virtrust-api.md)
- [Virtrust Shell 用户手册](003-virtrust-sh.md)
- [项目简介](001-introduction.md)

## 许可证

Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.