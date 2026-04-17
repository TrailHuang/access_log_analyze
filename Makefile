# 二进制文件名称
BINARY_NAME=access_log_analyzer

# Go 参数
GO=go
GOFLAGS=-v

# 版本信息(可通过命令行覆盖)
VERSION?=1.0.0
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# ldflags 用于嵌入版本信息
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

# 默认目标：编译双架构
.PHONY: all
all: build-amd64 build-arm64

# 编译 Linux x86_64
.PHONY: build-amd64
build-amd64:
	@echo "==> 构建 $(BINARY_NAME) (linux/amd64)..."
	@mkdir -p build
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o build/$(BINARY_NAME)_linux_amd64 ./cmd/access_log_analyzer/
	@echo "==> 完成: build/$(BINARY_NAME)_linux_amd64"

# 编译 Linux aarch64
.PHONY: build-arm64
build-arm64:
	@echo "==> 构建 $(BINARY_NAME) (linux/arm64)..."
	@mkdir -p build
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) $(LDFLAGS) -o build/$(BINARY_NAME)_linux_arm64 ./cmd/access_log_analyzer/
	@echo "==> 完成: build/$(BINARY_NAME)_linux_arm64"

# 清理构建文件
.PHONY: clean
clean:
	@echo "==> 清理构建文件..."
	@rm -rf build
	@echo "==> 清理完成"

# 运行程序
.PHONY: run
run: build-amd64
	@echo "==> 运行 $(BINARY_NAME)..."
	./build/$(BINARY_NAME)_linux_amd64 $(ARGS)

# 测试
.PHONY: test
test:
	@echo "==> 运行测试..."
	$(GO) test -v ./...

# 格式化代码
.PHONY: fmt
fmt:
	@echo "==> 格式化代码..."
	$(GO) fmt ./...

# 代码检查
.PHONY: vet
vet:
	@echo "==> 运行 go vet..."
	$(GO) vet ./...

# 下载依赖
.PHONY: deps
deps:
	@echo "==> 下载依赖..."
	$(GO) mod download
	$(GO) mod tidy

# 显示版本信息
.PHONY: version
version:
	@echo "版本: $(VERSION)"
	@echo "构建时间: $(BUILD_TIME)"
	@echo "Git提交: $(GIT_COMMIT)"

# 帮助信息
.PHONY: help
help:
	@echo "可用目标:"
	@echo "  all          - 编译双架构 x86_64 + aarch64 (默认)"
	@echo "  build-amd64  - 仅编译 linux/amd64"
	@echo "  build-arm64  - 仅编译 linux/arm64"
	@echo "  clean        - 清理构建文件"
	@echo "  run          - 编译amd64并运行 (使用 ARGS 参数)"
	@echo "  test         - 运行测试"
	@echo "  fmt          - 格式化代码"
	@echo "  vet          - 代码检查"
	@echo "  deps         - 下载依赖"
	@echo "  version      - 显示版本信息"
	@echo "  help         - 显示此帮助信息"
	@echo ""
	@echo "示例:"
	@echo "  make                          # 编译双架构"
	@echo "  make build-amd64              # 仅编译x86_64"
	@echo "  make VERSION=2.0.0            # 指定版本号编译"
	@echo "  make clean                    # 清理"
	@echo "  ./build.sh 2.0.0              # 编译+打包为tar.gz"
