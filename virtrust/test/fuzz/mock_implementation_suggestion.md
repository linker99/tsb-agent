# Mock实现总结

## 当前实现状况

### ✅ 已完成的Mock系统

项目已经在 `src/virtrust/dllib/mock/` 中实现了完整的Mock方案：

#### 1. 目录结构

```
src/virtrust/dllib/mock/
├── libvirt_mock.h      # libvirt Mock接口
├── libvirt_mock.cpp    # libvirt Mock实现
├── libguestfs_mock.h   # libguestfs Mock接口
└── libguestfs_mock.cpp # libguestfs Mock实现
```

#### 2. 条件编译

**已实现**：使用 `VIRTRUST_MOCK` 宏控制Mock/真实实现切换

- `src/virtrust/dllib/libvirt.h` - 条件编译包含libvirt Mock
- `src/virtrust/dllib/libguestfs.h` - 条件编译包含libguestfs Mock
- 统一的类型别名：`using Libvirt = LibvirtMock`

#### 3. 核心特性

- **条件编译**：`VIRTRUST_MOCK` 控制实现切换
- **单例模式**：确保全局唯一的Mock实例
- **安全默认值**：所有Mock函数返回有效的假指针和安全值
- **内存管理**：适当的内存分配和释放模拟

注意使用安全函数，在securec.h系统头文件中。
用法：
```
if (strncpy_s(char *strDest, size_t destMax, const char *strSrc, size_t count) != EOK) {
}
```

#### 4. 已实现的Mock库

**✅ libvirt Mock**：
- 完整的域生命周期管理（创建、启动、停止、销毁）
- 域查询和信息获取（状态、UUID、内存、CPU）
- 迁移功能支持
- 动态域数量（根据flags返回不同数量）
- 基于指针的状态映射（不同指针返回不同域信息）

**✅ libguestfs Mock**：
- 虚拟机镜像挂载和文件系统操作
- 文件存在性和类型检查
- 智能文件内容Mock（根据路径返回不同内容）
- 操作系统检测和挂载点管理
- GRUB配置和BIOS版本模拟

libguestfs_mock的 guestfs_read_file 函数，需要根据不同文件名返回特定内容，总结如下：
1.grub.cfg
2行内容：
"linux /vmlinuz-6.6.0\ninitrd /initramfs-6.6.0"

2.bios_version
1行内容：
"6.66"

3.grubaa64.efi
2行内容：
"GRUB  version\n6.66"

4.shimaa64.efi
内容随机即可

5.vmlinuz-6.6.0
内容随机即可

6.initramfs-6.6.0
内容随机即可



#### 5. 构建配置

- **Fuzz模式** (`CMAKE_BUILD_TYPE=Fuzz`)：自动使用Mock实现
- **生产模式**：使用真实库实现
- CMake自动包含Mock源文件：`src/virtrust/dllib/CMakeLists.txt`

#### 6. 清理完成

**✅ 已删除**：
- `src/virtrust/utils/foreign_mounter.cpp` 中的 `VIRTRUST_MOCK` 条件编译代码
- 所有内联Mock实现，统一使用模块化Mock系统

## 使用方式

### Fuzz构建
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Fuzz -DBUILD_TEST=On ..
make -j4
```

### 生产构建
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TEST=On ..
make -j4
```

## 优势总结

1. **代码整洁**：移除分散的条件编译，集中管理Mock实现
2. **易于维护**：统一的Mock目录和接口
3. **类型安全**：使用条件编译的类型别名
4. **功能完整**：支持所有必要的libvirt和libguestfs操作
5. **构建简单**：CMake自动处理包含关系

### ✅ gRPC Client Mock (新增)

**已实现**：完整的gRPC客户端Mock实现用于虚拟机迁移功能

#### 5. Mock目录结构更新

```
src/virtrust/link/mock/
├── grpc_client_mock.h      # gRPC客户端Mock接口
└── grpc_client_mock.cpp    # gRPC客户端Mock实现
```

#### 6. 已实现的gRPC Mock函数

**✅ UdsClientMock**：
- `DomainMigrate` - 迁移入口函数，总是返回成功

**✅ RpcClientMock**：
- `PrepareMigration` - 准备迁移阶段
- `ExchangePkAndReport` - 交换公钥和信任报告阶段
- `StartMigration` - 开始迁移阶段
- `SendVRsourceData` - 传输虚拟机资源数据阶段
- `NotifyVRMigrateResult` - 通知迁移结果阶段

#### 7. Mock功能特性

- **完整数据模拟**：生成符合proto定义的完整响应数据
- **信任报告生成**：包含PCR值、主机ID、TPCM ID等完整信任链信息
- **密钥数据模拟**：生成公钥和TCM2密钥的Mock数据
- **安全函数使用**：使用securec.h中的安全函数
- **状态一致性**：所有Mock函数返回成功状态，便于fuzz测试

#### 8. 条件编译集成

## 已完成的所有Mock实现

**✅ libvirt Mock** - src/virtrust/dllib/mock/libvirt_mock.cpp 完整的虚拟域管理Mock实现
**✅ libguestfs Mock** -src/virtrust/dllib/mock/libguestfs_mock.cpp  完整的虚拟机文件系统操作Mock实现
**✅ tsb_agent Mock src/tsb_agent/mock/tsb_agent_adaptor_simple.cpp - 模拟TSB-agent调用
**✅ gRPC Client Mock** -src/virtrust/link/mock/grpc_client_mock.cpp 完整的虚拟机迁移gRPC客户端Mock实现
**✅ file_io Mock** - src/virtrust/utils/mock/file_io_mock.cpp  模拟读取某些文件

#### 9. mock的接口概率返回失败-模拟某些异常场景

**✅ 已实现的概率性失败机制**

已在所有主要mock系统中添加统一的概率失败函数，默认10%失败概率：

**已实现的Mock系统**
- **libvirt Mock** - 虚拟化操作失败
- **libguestfs Mock** - 文件系统操作失败
- **tsb_agent Mock** - TSB代理操作失败
- **gRPC Client Mock** - 迁移通信失败

**实现方式**
- **统一失败函数**：`ShouldMockFail(概率=0.1)`
- **简单设计**：在关键函数入口处调用失败函数
- **全面覆盖**：测试错误处理路径和恢复机制