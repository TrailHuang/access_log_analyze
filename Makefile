# 二进制文件名称
BINARY_NAME=access_log_analyzer

# Go 参数
GO=go
GOFLAGS=-v

# 构建参数 - 针对 Linux x86_64
GOOS=linux
GOARCH=amd64

# 版本信息(可通过命令行覆盖)
VERSION?=1.0.0
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# ldflags 用于嵌入版本信息
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

# 默认目标
.PHONY: all
all: build package

# 构建 Linux x86_64 二进制文件
.PHONY: build
build:
	@echo "==> 构建 $(BINARY_NAME) (Linux x86_64)..."
	@mkdir -p build
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(GOFLAGS) $(LDFLAGS) -o build/$(BINARY_NAME) main.go
	@echo "==> 构建完成: build/$(BINARY_NAME)"

# 打包二进制和配置文件
.PHONY: package
package: build
	@echo "==> 打包 $(BINARY_NAME) 和 config.json..."
	@mkdir -p access_log_analyzer_release	
	@cp build/$(BINARY_NAME) access_log_analyzer_release/
	@cp config.json access_log_analyzer_release/
	@tar -czf $(BINARY_NAME)_$(VERSION).tar.gz access_log_analyzer_release 
	@echo "==> 打包完成: $(BINARY_NAME)_$(VERSION).tar.gz"

# 清理构建文件
.PHONY: clean
clean:
	@echo "==> 清理构建文件..."
	@rm -rf build
	@echo "==> 清理完成"

# 运行程序
.PHONY: run
run: build
	@echo "==> 运行 $(BINARY_NAME)..."
	./build/$(BINARY_NAME) $(ARGS)

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
	@echo "  all/build   - 构建并打包 (默认)"
	@echo "  build       - 仅构建 Linux x86_64 二进制文件"
	@echo "  package     - 打包二进制文件和config.json为tar.gz"
	@echo "  clean       - 清理构建文件"
	@echo "  run         - 构建并运行程序 (使用 ARGS 参数)"
	@echo "  test        - 运行测试"
	@echo "  fmt         - 格式化代码"
	@echo "  vet         - 代码检查"
	@echo "  deps        - 下载依赖"
	@echo "  version     - 显示版本信息"
	@echo "  help        - 显示此帮助信息"
	@echo ""
	@echo "示例:"
	@echo "  make                          # 构建并打包"
	@echo "  make build                    # 仅构建"
	@echo "  make package                  # 打包"
	@echo "  make clean                    # 清理"
	@echo "  make run ARGS=/path/to/logs   # 运行并指定目录"
	@echo "  make version VERSION=2.0.0    # 指定版本号"
