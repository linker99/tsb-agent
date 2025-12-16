# 统一Domain Fuzzer实现方案

本文档描述了如何将多个单独的Domain fuzzer合并成一个统一的fuzzer，以便：
- 获得整体业务覆盖率
- 共用语料库资源
- 简化fuzzing流程管理

## 当前实现状态

✅ **已完成**：`test/fuzz/fuzz_domain_all.cpp` - 统一的Domain fuzzer入口
✅ **已完成**：`test/fuzz/scripts/generate_seed_corpus.py` - CSV种子生成脚本
✅ **已完成**：`test/fuzz/scripts/fuzz_inputs.csv` - 参数输入文件
✅ **已完成**：动态参数解析和CSV数据利用
✅ **已完成**：最小size限制优化

## 第一步：统一输入格式设计

采用简洁高效的op_id + payload格式：

```text
[op_id(1字节)] + [payload(变长)]
```

**op_id映射**：
- `0` → DomainCreate (虚拟机创建)
- `1` → DomainDestroy (虚拟机销毁)
- `2` → DomainStart (虚拟机启动)
- `3` → DomainList (虚拟机列表)
- `4` → DomainUndefine (虚拟机删除)
- `5` → DomainMigrate (虚拟机迁移)

## 第二步：种子数据格式设计

每个接口都有特定的二进制种子格式，便于参数解析：

### DomainCreate (op_id=0)
```
[op_id(1)] + [arg_count(1)] + [arg1\x00] + [arg2\x00] + ... + [argN\x00]
```

### DomainDestroy/Start/Undefine (op_id=1,2,4)
```
[op_id(1)] + [domain_name\x00] + [flags(4字节)] + [is_only_tsb(1字节)]
```

### DomainList (op_id=3)
```
[op_id(1)] + [flags(4字节)] + [print_err_to_cli(1字节)]
```

### DomainMigrate (op_id=5)
```
[op_id(1)] + [domain_name\x00] + [dest_uri\x00] + [flags(4字节)]
```

## 第三步：核心实现文件

### `test/fuzz/fuzz_domain_all.cpp`
- **6个helper函数**：每个Domain API一个helper
- **动态参数解析**：从fuzz数据中提取实际参数
- **边缘用例测试**：包含nullptr、无效参数等测试
- **统一入口**：`LLVMFuzzerTestOneInput`分发到对应helper

### `test/fuzz/fuzz_helper.h`
- **参数解析函数**：
  - `ExtractVirtArgs()` - 解析virt-install参数
  - `ExtractDomainDestroyParams()` - 解析domainName+flags+isOnlyTsb
  - `ExtractDomainListParams()` - 解析flags+printErrToCli
  - `ExtractDomainMigrateParams()` - 解析domainName+destUri+flags
- **Mock连接管理**：`GetGlobalConn()`和`CreateConnCtx()`
- **辅助函数**：各种数据提取和验证函数

### `test/fuzz/scripts/generate_seed_corpus.py`
- **CSV解析**：从`fuzz_inputs.csv`读取测试参数
- **二进制序列化**：将CSV参数转换为对应格式的二进制种子
- **op_id映射**：支持6个Domain操作类型
- **最小size检查**：确保种子满足最小size要求

## 第四步：语料库管理

### 1. 参数输入文件 (`fuzz_inputs.csv`)
CSV格式存储测试用例，支持注释：
```csv
# Domain Create test cases
create, /usr/bin/virt-install, --name=test-domain-1, --memory=1024, --vcpus=2, --disk-size=10G
create, /usr/bin/virt-install, --import, --name=test-vm, --ram=2048, --vcpus=4

# Domain Destroy test cases
destroy, test-domain-1, 0, true
destroy, 12345678-1234-1234-1234-123456789001, 0, true

# Domain Start test cases
start, test-domain-1, 0, true
start, test-domain-2, 1, false

# Domain List test cases
list, 0, true
list, 1, false
list, 3, true

# Domain Undefine test cases
undefine, test-domain-1, 0, true
undefine, test-domain-2, 1, false

# Domain Migrate test cases
migrate, test-domain-1, qemu+tcp://192.168.1.100:16509/system, 0
migrate, test-domain-2, qemu+tls://192.168.1.101:16509/system, 1
```

### 2. 种子生成命令
```bash
cd test/fuzz/scripts
python3 generate_seed_corpus.py
```

生成`corpus/fuzz_all_ops/`目录下的二进制种子文件。

### 3. 语料库转换脚本（可选）
```bash
cd test/fuzz/scripts
chmod +x convert_corpus.sh
./convert_corpus.sh
```

将现有单个fuzzer的语料库转换为统一格式。

## 第五步：构建和运行

### CMake配置
已在`test/fuzz/CMakeLists.txt`中添加：
```cmake
add_fuzzer(fuzz_all_ops SOURCE_FILE fuzz_domain_all.cpp)
```

### 构建命令
```bash
./build.sh fuzz
```

### 运行fuzzer
```bash
cd test/fuzz/scripts
./run_fuzz.sh fuzz_all_ops 60
```

### 覆盖率报告
生成单一的综合覆盖率报告，包含所有Domain操作的覆盖情况。

## 实现优势

### ✅ **技术优势**
1. **参数动态解析**：不再依赖固定内存偏移
2. **CSV数据完全利用**：所有输入参数都会被正确使用
3. **API签名精确匹配**：每个helper函数符合实际API要求
4. **最小size优化**：合理的最小size限制，减少填充浪费

### ✅ **工程优势**
1. **统一管理**：一个fuzzer管理所有Domain操作
2. **语料库共享**：避免重复工作，提高效率
3. **覆盖率集中**：获得整体业务覆盖率视图
4. **易于维护**：新增操作只需添加helper和op_id映射

### ✅ **Mock友好**
- 支持Fuzz模式自动启用Mock实现
- 兼容libvirt和TSB Agent的Mock
- 无文件I/O，提高fuzzing速度

## 扩展指南

### 添加新的Domain操作
1. **添加op_id映射**：在Python脚本的`OP_MAP`中添加新条目
2. **实现helper函数**：在`fuzz_helper.h`中添加参数解析函数
3. **更新主分发器**：在`LLVMFuzzerTestOneInput`中添加case
4. **添加CSV测试用例**：在`fuzz_inputs.csv`中添加参数示例
5. **更新最小size**：确保C++和Python的一致性

### 调试和验证
1. **种子验证**：使用`xxd`检查生成的二进制种子格式
2. **日志输出**：启用详细日志观察参数解析过程
3. **单步调试**：使用GDB调试特定参数处理逻辑
4. **覆盖率分析**：对比单个fuzzer和统一fuzzer的覆盖率差异

## 架构总结

```
CSV输入 → Python脚本 → 二进制种子 → fuzz_domain_all.cpp → Domain APIs → 统一覆盖率
```

这个统一的fuzzer架构提供了高效、可维护、可扩展的Domain操作测试方案。