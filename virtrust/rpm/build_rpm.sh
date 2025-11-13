#!/usr/bin/env bash
set -euo pipefail

# Package source, fetch dependency archives, and run rpmbuild.
# Usage: rpm/build_rpm.sh [SOURCES_DIR]
# - SOURCES_DIR defaults to ~/rpmbuild/SOURCES

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
SPEC_FILE="$ROOT_DIR/rpm/TSB-agent.spec"

if [[ ! -f "$SPEC_FILE" ]]; then
  echo "ERROR: Spec file not found: $SPEC_FILE" >&2
  exit 1
fi

# Extract Name and Version from spec
PKG_NAME=$(awk -F: '/^Name:/ {gsub(/^[ \t]+/,"",$2); print $2; exit}' "$SPEC_FILE")
PKG_VERSION=$(awk -F: '/^Version:/ {gsub(/^[ \t]+/,"",$2); print $2; exit}' "$SPEC_FILE")

if [[ -z "${PKG_NAME:-}" || -z "${PKG_VERSION:-}" ]]; then
  echo "ERROR: Failed to parse Name/Version from $SPEC_FILE" >&2
  exit 1
fi

# Where to put Source0..N
DEST_DIR=${1:-"$HOME/rpmbuild/SOURCES"}
mkdir -p "$DEST_DIR"

SRC_TARBALL="$DEST_DIR/${PKG_NAME}-${PKG_VERSION}.tar.gz"

echo "==> Packaging source into: $SRC_TARBALL"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
STAGE="$TMPDIR/${PKG_NAME}-${PKG_VERSION}"
mkdir -p "$STAGE"
rsync -a \
  --exclude '.git' \
  --exclude '.idea' \
  --exclude 'build' \
  --exclude '*.o' \
  --exclude '*.a' \
  --exclude '*.so' \
  --exclude '*.so.*' \
  --exclude '*.swp' \
  --exclude '*~' \
  "$ROOT_DIR"/ "$STAGE"/
tar -C "$TMPDIR" -czf "$SRC_TARBALL" "${PKG_NAME}-${PKG_VERSION}"
rm -rf "$TMPDIR"
trap - EXIT

echo "==> Downloading dependency archives into: $DEST_DIR"
# Helper: curl or wget
_fetch() {
  local url="$1" out="$2"
  if [[ -f "$out" ]]; then
    echo "[skip] $out already exists"
    return
  fi
  if command -v curl >/dev/null 2>&1; then
    curl -L --fail --retry 3 -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$out" "$url"
  else
    echo "ERROR: Neither curl nor wget found for downloading $url" >&2
    return 1
  fi
}

# 依赖下载地址：与 cmake/deps/*.cmake 中的 gitee 源保持一致。
# 注意：仅更改下载源，不更改本地保存的文件名，以便与 .spec 中的 Source1..N 对齐。
# - gtest:      gitee.com/mirrors/googletest.git (tag: v1.15.2)
# - openssl:    gitee.com/mirrors/openssl.git    (tag: openssl-3.3.2)
# - rapidjson:  gitee.com/Tencent/RapidJSON.git  (tag: v1.1.0)
# - spdlog:     gitee.com/mirrors_trending/spdlog.git (tag: v1.14.1)
# - libboundscheck: gitee.com/openeuler/libboundscheck (branch: master)

# Gitee 通用归档下载路径格式：
#   https://gitee.com/<org>/<repo>/repository/archive/<ref>.tar.gz

GTEST_URL="https://gitee.com/mirrors/googletest/repository/archive/v1.15.2.tar.gz"
OPENSSL_URL="https://gitee.com/mirrors/openssl/repository/archive/openssl-3.3.2.tar.gz"
RAPIDJSON_URL="https://gitee.com/Tencent/RapidJSON/repository/archive/v1.1.0.tar.gz"
SPDLOG_URL="https://gitee.com/mirrors_trending/spdlog/repository/archive/v1.14.1.tar.gz"
LIBBOUNDSCHECK_URL="https://gitee.com/openeuler/libboundscheck/repository/archive/master.tar.gz"

# Output file names for SourceN (keep in sync with spec!)
GTEST_OUT="$DEST_DIR/googletest-v1.15.2.tar.gz"
OPENSSL_OUT="$DEST_DIR/openssl-3.3.2.tar.gz"
RAPIDJSON_OUT="$DEST_DIR/rapidjson-v1.1.0.tar.gz"
SPDLOG_OUT="$DEST_DIR/spdlog-v1.14.1.tar.gz"
LIBBOUNDSCHECK_OUT="$DEST_DIR/libboundscheck.tar.gz"

_fetch "$GTEST_URL" "$GTEST_OUT"
_fetch "$OPENSSL_URL" "$OPENSSL_OUT"
_fetch "$RAPIDJSON_URL" "$RAPIDJSON_OUT"
_fetch "$SPDLOG_URL" "$SPDLOG_OUT"
_fetch "$LIBBOUNDSCHECK_URL" "$LIBBOUNDSCHECK_OUT"

echo "==> Generating checksums"
MANIFEST="$DEST_DIR/${PKG_NAME}-${PKG_VERSION}-sources.SHA256"
{
  sha256sum "$SRC_TARBALL" || true
  sha256sum "$GTEST_OUT" || true
  sha256sum "$OPENSSL_OUT" || true
  sha256sum "$RAPIDJSON_OUT" || true
  sha256sum "$SPDLOG_OUT" || true
  sha256sum "$LIBBOUNDSCHECK_OUT" || true
} > "$MANIFEST"

echo "==> Preparing rpmbuild tree"
RPMBUILD_ROOT="$HOME/rpmbuild"
mkdir -p "$RPMBUILD_ROOT"/{SPECS,SRPMS,RPMS,BUILD,BUILDROOT}

# 可以直接用仓库里的 spec，不必复制，但有些人喜欢 copy 一份到 SPECS 里：
cp -f "$SPEC_FILE" "$RPMBUILD_ROOT/SPECS/"

echo "==> Running rpmbuild"
rpmbuild -ba "$SPEC_FILE" \
  --define "_sourcedir $DEST_DIR" \
  --define "_specdir $ROOT_DIR/rpm" \
  --define "_srcrpmdir $RPMBUILD_ROOT/SRPMS" \
  --define "_rpmdir $RPMBUILD_ROOT/RPMS" \
  --define "_builddir $RPMBUILD_ROOT/BUILD" \
  --define "_buildrootdir $RPMBUILD_ROOT/BUILDROOT"

cat <<EOF

All done.
  - Source0: $SRC_TARBALL
  - Extra sources:
      $GTEST_OUT
      $OPENSSL_OUT
      $RAPIDJSON_OUT
      $SPDLOG_OUT
      $LIBBOUNDSCHECK_OUT
  - Checksums: $MANIFEST
  - RPMs in:  $RPMBUILD_ROOT/RPMS
  - SRPM in:  $RPMBUILD_ROOT/SRPMS

EOF
