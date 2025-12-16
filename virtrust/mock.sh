#!/usr/bin/env bash
set -euo pipefail

ROOT="$(pwd)"
OUT="$ROOT/coverage_out"
mkdir -p "$OUT"

# 通用的 lcov 过滤规则（按你原来的）
LCOV_EXCLUDES=(
  --exclude "build/*"
  --exclude "external/*"
  --exclude "/usr/*"
)

# ========== 1) domain_test 覆盖率 ==========
rm -rf build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Coverage -DUSE_MOCK_TSB_AGENT=ON -DENABLE_MOCK=ON
cmake --build build -j 16

pushd build >/dev/null
./bin/domain_test

# 2) capture 成 info（这一步就是“拷贝出覆盖率数据”的最佳方式）
lcov --capture --directory . --base-directory "$ROOT" \
  "${LCOV_EXCLUDES[@]}" \
  --output-file "$OUT/cov_domain_test.info" \
  --ignore-errors mismatch,inconsistent,unused
popd >/dev/null


# ========== 3) 其余 UT 覆盖率 ==========
#rm -rf build
#cmake -S . -B build -DCMAKE_BUILD_TYPE=Coverage
#cmake --build build -j 16
#
#pushd build >/dev/null
#ctest --output-on-failure
#
## 4) capture 成 info
#lcov --capture --directory . --base-directory "$ROOT" \
#  "${LCOV_EXCLUDES[@]}" \
#  --output-file "$OUT/cov_other_ut.info" \
#  --ignore-errors mismatch,inconsistent,unused
#popd >/dev/null
#
#
## ========== 5) 合并 + 生成 HTML ==========
#lcov -a "$OUT/cov_domain_test.info" -a "$OUT/cov_other_ut.info" \
#  -o "$OUT/coverage_merged.info"
#
#genhtml "$OUT/coverage_merged.info" \
#  --output-directory "$OUT/html" \
#  --ignore-errors inconsistent
#
#echo "DONE: $OUT/html/index.html"
