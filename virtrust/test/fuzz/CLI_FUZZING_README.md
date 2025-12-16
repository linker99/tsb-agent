# CLI Fuzzing - 使用说明

本文档提供了virtrust CLI工具fuzzing的快速使用指南。

## 前置条件

- Clang编译器（libFuzzer需要）
- Python 3（种子生成脚本）
- CMake 3.10+

## 快速开始

### 1. 构建CLI Fuzzer

```bash
# 创建构建目录
mkdir build && cd build

# 配置fuzzing构建
cmake -DBUILD_FUZZ_CLI=On -DCMAKE_BUILD_TYPE=Fuzz ..

# 或者使用便捷脚本
./build.sh fuzz
```

### 2. 生成种子数据

```bash
cd test/fuzz/scripts
python3 cli_seed_generator.py
```

### 3. 运行Fuzzing

```bash
# 基本运行（60秒）
./run_fuzz.sh fuzz_cli 60

# 持续运行（按Ctrl+C停止）
./run_fuzz.sh fuzz_cli 0

# 指定输出目录
mkdir -p /tmp/cli_fuzz_output
./run_fuzz.sh fuzz_cli 300 /tmp/cli_fuzz_output
```

## 可用的种子类型

种子生成器会创建以下类型的测试用例：

- **基本命令**：create, start, destroy, undefine, list, migrate
- **选项组合**：-d, -c, --connect, --debug等
- **帮助命令**：-h, --help, -v, --version
- **边界情况**：长参数、特殊字符、错误选项
- **国际化测试**：中文和特殊字符支持
- **复杂场景**：多选项组合、完整生命周期

## 故障排除

### 编译错误

如果遇到链接错误：
```bash
# 确保使用了正确的编译器
export CC=clang
export CXX=clang++

# 清理并重新构建
rm -rf build
mkdir build && cd build
cmake -DBUILD_FUZZ_CLI=On -DCMAKE_BUILD_TYPE=Fuzz ..
```

### 运行时错误

如果遇到段错误或内存问题：
```bash
# 使用ASan构建检测内存问题
cmake -DBUILD_FUZZ_CLI=On -DCMAKE_BUILD_TYPE=Asan ..
```

### 种子文件问题

如果种子文件损坏：
```bash
# 重新生成种子
cd test/fuzz/scripts
rm -rf ../corpus/fuzz_cli/*
python3 cli_seed_generator.py
```

## 覆盖率分析

```bash
# 生成覆盖率报告
./build.sh coverage

# CLI特定覆盖率
lcov --capture --directory . --output-file coverage_cli.info
lcov --extract coverage_cli.info '*/src/virtrust-sh/*' --output-file coverage_cli_virtrust.info
genhtml coverage_cli_virtrust.info --output-directory coverage_cli_report

# 查看报告
firefox coverage_cli_report/index.html
```

## 扩展测试用例

要添加新的CLI测试用例：

1. 编辑 `test/fuzz/scripts/cli_seed_generator.py`
2. 在 `CLI_COMMANDS` 列表中添加新命令
3. 运行种子生成脚本：
   ```bash
   python3 cli_seed_generator.py
   ```

## 性能调优

### 提高fuzzing速度

1. 确保使用SSD存储
2. 增加内存限制
3. 使用多核并行fuzzing

### 内存限制

```bash
# 限制fuzzer内存使用
export ASAN_OPTIONS=detect_leaks=1:quarantine_size_mb=100
./run_fuzz.sh fuzz_cli 300
```

## 文件结构

```
test/fuzz/
├── fuzz_cli.cpp                    # libFuzzer接口实现
├── scripts/
│   ├── cli_seed_generator.py       # 种子生成脚本
│   └── run_fuzz.sh                # fuzzer运行脚本
├── corpus/fuzz_cli/               # 种子文件目录
└── CMakeLists.txt                 # 构建配置
```

## 相关文档

- `test/fuzz/FUZZ_CLI.md` - 详细的技术实现文档
- `docs/003-virtrust-sh.md` - CLI工具使用说明

## 技术支持

如果遇到问题：

1. 检查编译器是否为Clang
2. 确认所有依赖项已正确安装
3. 查看构建日志中的错误信息
4. 使用ASan或TSan构建检测内存/线程问题