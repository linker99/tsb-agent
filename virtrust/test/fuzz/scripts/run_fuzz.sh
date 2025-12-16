#!/usr/bin/env bash
#
# 一键运行 libFuzzer + 生成覆盖率报告 的脚本
# 用法：
#   ./run_fuzz.sh <fuzz_binary_name> [max_total_time_sec]
#
# 示例：
#   ./run_fuzz.sh fuzz_domain_migrate
#   ./run_fuzz.sh fuzz_domain_create 120
#
# 约定：
#   1. FUZZ_BIN_DIR 中放着你的 fuzzer 可执行文件
#   2. corpus/<binary_name>/ 为对应的语料库目录（如果不存在会自动创建）
#   3. 所有报告输出到 reports/<binary_name>/timestamp/ 目录

set -euo pipefail

######################## 用户可按需要修改的配置 ########################

# fuzzer 可执行文件所在目录（你可以改成 build/fuzz 等）
FUZZ_BIN_DIR="../../../build/bin"

# 语料库根目录
CORPUS_ROOT_DIR="../corpus"

# 报告根目录
REPORT_ROOT_DIR="../reports"

# 使用的 llvm 工具
LLVM_PROFDATA_BIN="llvm-profdata"
LLVM_COV_BIN="llvm-cov"

# virtrust-share库目录
VIRTRUST_SHARED_SO="../../../build/lib64/libvirtrust-shared.so"

########################################################################

if [[ $# -lt 1 ]]; then
    echo "用法: $0 <fuzz_binary_name> [max_total_time_sec]" >&2
    exit 1
fi

FUZZ_NAME="$1"
MAX_TIME="${2:-60}"   # 默认跑 60 秒

FUZZ_BIN="${FUZZ_BIN_DIR%/}/${FUZZ_NAME}"

if [[ ! -x "${FUZZ_BIN}" ]]; then
    echo "错误：找不到可执行文件：${FUZZ_BIN}" >&2
    exit 1
fi

# 语料库目录： corpus/<FUZZ_NAME>/
CORPUS_DIR="${CORPUS_ROOT_DIR%/}/${FUZZ_NAME}"
mkdir -p "${CORPUS_DIR}"

# 报告目录： reports/<FUZZ_NAME>/yyyyMMdd_HHmmss/
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_DIR="${REPORT_ROOT_DIR%/}/${FUZZ_NAME}/${TIMESTAMP}"
mkdir -p "${REPORT_DIR}"

echo "=== 运行配置 ==="
echo "  Fuzzer 可执行文件: ${FUZZ_BIN}"
echo "  语料库目录:        ${CORPUS_DIR}"
echo "  报告目录:          ${REPORT_DIR}"
echo "  运行时长:          ${MAX_TIME} 秒"
echo

# profraw 文件路径
PROFRAW_FILE="${REPORT_DIR}/profile.profraw"
PROFDATA_FILE="${REPORT_DIR}/profile.profdata"
FUZZ_LOG="${REPORT_DIR}/fuzz.log"
STATS_TXT="${REPORT_DIR}/stats.txt"
COV_HTML_DIR="${REPORT_DIR}/coverage_html"
COV_SUMMARY_TXT="${REPORT_DIR}/coverage_summary.txt"

echo "=== 开始 fuzz 运行（libFuzzer） ==="
echo "  日志: ${FUZZ_LOG}"
echo
START_TIME=$(date +%s)

# 运行 fuzzer，收集 profile 和统计数据
# -print_final_stats=1 会在退出时打印最终统计
# 通过 tee 把输出同时写到终端和日志文件
#ASAN_OPTIONS="detect_leaks=1:fast_unwind_on_malloc=0:malloc_context_size=30:symbolize=1:halt_on_error=1" \
##LSAN_OPTIONS="report_objects=1" \
LLVM_PROFILE_FILE="${PROFRAW_FILE}" \
    "${FUZZ_BIN}" \
    "${CORPUS_DIR}" \
    -max_total_time="${MAX_TIME}" \
    -print_final_stats=1 \
    2>&1 | tee "${FUZZ_LOG}"

echo
echo "=== fuzz 运行结束，开始生成统计信息 ==="
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
echo "=== fuzz 运行结束（实际耗时 ${ELAPSED} 秒） ==="
echo

# 提取以 stat:: 开头的行，保存为 stats.txt
grep '^stat::' "${FUZZ_LOG}" > "${STATS_TXT}" || true
echo "total_time_sec=${ELAPSED}" >> "${STATS_TXT}"
echo "统计信息已保存到: ${STATS_TXT}"
echo "内容示例（前几行）："
head -n 10 "${STATS_TXT}" || true
echo

# 如果没有生成 profraw，说明没有开启 -fprofile-instr-generate
if [[ ! -f "${PROFRAW_FILE}" ]]; then
    echo "警告：未找到 profile 文件 ${PROFRAW_FILE}"
    echo "请确认编译时加入：-fprofile-instr-generate -fcoverage-mapping"
    exit 0
fi

echo "=== 生成 llvm-profdata ==="
"${LLVM_PROFDATA_BIN}" merge -sparse "${PROFRAW_FILE}" -o "${PROFDATA_FILE}"

echo "=== 生成 llvm-cov HTML 覆盖率报告 ==="
mkdir -p "${COV_HTML_DIR}"
"${LLVM_COV_BIN}" show "${FUZZ_BIN}" \
    -object="${VIRTRUST_SHARED_SO}" \
    -instr-profile="${PROFDATA_FILE}" \
    -ignore-filename-regex='.*test/.*' \
    -ignore-filename-regex='.*_test\.cpp$' \
    -ignore-filename-regex='.*fuzz.*\.cpp$' \
    -ignore-filename-regex='.*\.pb\.cc$' \
    -ignore-filename-regex='.*\.grpc\.pb\.cc$' \
    -ignore-filename-regex='.*log.*' \
    -ignore-filename-regex='.*build.*' \
    -ignore-filename-regex='.*mock.*' \
    -format=html \
    -output-dir="${COV_HTML_DIR}" \
    >/dev/null

echo "HTML 覆盖率报告目录: ${COV_HTML_DIR}"
echo "  打开: ${COV_HTML_DIR}/index.html 即可查看行/函数覆盖率"
echo

echo "文本覆盖率概要: ${COV_SUMMARY_TXT}"
echo
echo "=== 完成 ==="
echo "  Fuzzer:        ${FUZZ_NAME}"
echo "  报告目录:      ${REPORT_DIR}"
echo "  统计信息:      ${STATS_TXT}"
echo "  覆盖率(HTML):  ${COV_HTML_DIR}/index.html"
