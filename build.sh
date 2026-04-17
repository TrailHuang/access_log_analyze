#!/bin/bash
set -e

# ===== 配置 =====
BINARY_NAME="access_log_analyzer"
VERSION=`cat VERSION.txt`
RELEASE_DIR="access_log_analyzer_release"
TAR_NAME="${BINARY_NAME}_${VERSION}.tar.gz"

# ===== 1. 编译（调用 Makefile） =====
echo "==> 编译双架构二进制 (VERSION=${VERSION})..."
make VERSION="${VERSION}"

# ===== 2. 打包 =====
echo "==> 打包 ${TAR_NAME}..."
rm -rf "${RELEASE_DIR}"
mkdir -p "${RELEASE_DIR}"

cp build/${BINARY_NAME}_linux_amd64  "${RELEASE_DIR}/"
cp build/${BINARY_NAME}_linux_arm64  "${RELEASE_DIR}/"
cp config.json                        "${RELEASE_DIR}/"
cp 使用说明.md            "${RELEASE_DIR}/"

tar -czf "${TAR_NAME}" "${RELEASE_DIR}"
rm -rf "${RELEASE_DIR}"

echo "==> 打包完成: ${TAR_NAME}"
echo "    包含文件:"
echo "      ${BINARY_NAME}_linux_amd64   (x86_64)"
echo "      ${BINARY_NAME}_linux_arm64   (aarch64)"
echo "      config.json"
echo "      FILTER_CONFIG_README.md"
