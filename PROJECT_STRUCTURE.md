# Access Log Analyzer - 项目结构说明

## 项目概述

访问日志分析工具，用于分析tar.gz格式的访问日志文件，统计流量信息并导出CSV报告。

## 项目结构

```
access_log_analyze/
├── cmd/
│   └── access_log_analyzer/
│       └── main.go              # 程序入口，参数解析和模块调用
├── internal/
│   ├── analyzer/                # 核心分析模块
│   │   ├── analyzer.go          # 日志解析、并发处理、CSV导出
│   │   ├── filter.go            # 过滤逻辑（通配符匹配）
│   │   └── parser.go            # 时间解析、字段映射
│   ├── config/                  # 配置管理模块
│   │   └── config.go            # 配置文件加载和参数合并
│   └── merger/                  # CSV合并模块
│       ├── exporter.go          # CSV导出和帮助信息
│       └── merger.go            # CSV合并和TopN提取
├── pkg/
│   └── models/                  # 数据模型
│       └── models.go            # 数据结构定义
├── build/                       # 构建输出目录
├── main.go                      # 原始单文件版本（备份）
├── main.go.backup               # 重构前的备份
├── Makefile                     # 构建脚本
├── go.mod                       # Go模块定义
├── go.sum                       # 依赖校验文件
└── config.json                  # 配置文件示例
```

## 模块说明

### 1. pkg/models - 数据模型层

定义核心数据结构：
- `TrafficStats` - 流量统计数据
- `CSVRecord` - CSV记录
- `LogFilters` - 日志过滤器

### 2. internal/config - 配置管理

- `LoadFilterConfig()` - 从JSON配置文件加载配置
- `MergeConfig()` - 合并配置文件和命令行参数（命令行优先级更高）

### 3. internal/analyzer - 核心分析器

#### filter.go - 过滤逻辑
- `MatchFilter()` - 检查值是否匹配过滤条件
- `ParseFilterPatterns()` - 解析过滤模式

#### parser.go - 解析器
- `ExtractTimeFromFileName()` - 从文件名提取时间
- `ParseTime()` - 解析时间字符串
- `IsFileInTimeRange()` - 检查文件是否在时间范围内
- `ParseFieldNames()` - 解析字段名到索引的映射

#### analyzer.go - 主分析器
- `ProcessTarGz()` - 处理单个tar.gz文件
- `ProcessFilesConcurrent()` - 并发处理多个文件
- `PrintResults()` - 输出统计结果（表格+CSV）
- `ExportToCSV()` - 导出CSV文件
- `GenerateTempCSV()` - 生成临时CSV快照
- `FormatBytes()` - 格式化字节数

**对象池优化**：
- `FieldValuesPool` - 复用map[string]string
- `KeyPartsPool` - 复用[]string
- `KeyBuilderPool` - 复用strings.Builder

### 4. internal/merger - CSV合并模块

#### exporter.go - 导出功能
- `ExportMergedCSV()` - 导出合并后的CSV
- `FormatBytes()` - 格式化字节数
- `PrintHelp()` - 打印帮助信息

#### merger.go - 合并逻辑
- `MergeCSVFiles()` - 合并目录下所有CSV文件
- `mergeCSVFilesByType()` - 合并同类型CSV
- `extractTopNPerKey()` - 提取每个分组的TopN记录

## 编译和运行

### 编译新版本（模块化）

```bash
# 编译到build目录
go build -o build/access_log_analyzer ./cmd/access_log_analyzer/

# 或直接编译到当前目录
go build -o access_log_analyzer_new ./cmd/access_log_analyzer/
```

### 编译原始版本（单文件）

```bash
go build -o access_log_analyzer_old main.go
```

### 使用Makefile

```bash
make          # 编译
make all      # 编译+打包
make clean    # 清理
```

## 使用示例

### 基本分析

```bash
# 分析目录下的日志文件
./access_log_analyzer /path/to/logs

# 指定统计字段和Top N
./access_log_analyzer -fields "sip,dip,domain" -top 20 /path/to/logs

# 按下行流量排序
./access_log_analyzer -sort down /path/to/logs
```

### 过滤和条件

```bash
# IP过滤（支持通配符）
./access_log_analyzer -sip "192.168.1.*,10.0.0.*" -dip "123.180.157.193" /path/to/logs

# 时间过滤
./access_log_analyzer -start 20260330000000 -end 20260331235959 /path/to/logs

# 使用配置文件
./access_log_analyzer -config filter_config.json /path/to/logs
```

### CSV合并

```bash
# 合并CSV并提取Top10
./access_log_analyzer -merge /path/to/csv_dir -fields "dip,domain" -top 10

# 输出文件：
# - merged_up.csv      (所有记录按上行流量排序)
# - merged_down.csv    (所有记录按下行流量排序)
# - top10_up.csv       (每个dip的上行流量Top10)
# - top10_down.csv     (每个dip的下行流量Top10)
```

## 重构说明

### 从单文件到模块化

**原始版本**：`main.go` (1880行)
- 所有功能在一个文件中
- 难以维护和测试
- 代码复用困难

**新版本**：模块化结构
- `cmd/` - 入口文件，仅负责参数解析
- `internal/` - 内部实现，按功能划分
- `pkg/` - 可复用的数据模型

### 优势

1. **可维护性**：每个模块职责清晰
2. **可测试性**：可以单独测试每个模块
3. **可复用性**：pkg下的包可被其他项目使用
4. **可读性**：文件更小，更容易理解
5. **扩展性**：添加新功能更容易

### 迁移指南

如果您正在使用原始的`main.go`：

1. **备份原始文件**：已完成（main.go.backup）
2. **使用新版本**：
   ```bash
   # 编译新版本
   go build -o access_log_analyzer ./cmd/access_log_analyzer/

   # 使用方式完全相同
   ./access_log_analyzer [参数]
   ```
3. **回退方案**：
   ```bash
   # 如果遇到问题，可以使用原始版本
   go build -o access_log_analyzer_old main.go.backup
   ```

## 技术栈

- **Go** 1.16+
- **github.com/olekukonko/tablewriter** - 表格输出
- **标准库**：archive/tar, compress/gzip, encoding/csv, encoding/json等

## 性能优化

1. **对象池**：减少GC压力
   - FieldValuesPool
   - KeyPartsPool
   - KeyBuilderPool

2. **并发处理**：多协程并行处理文件

3. **批量快照**：定期生成临时CSV，避免内存占用过高

## 开发规范

- `internal/` - 内部实现，不对外暴露
- `pkg/` - 公共包，可被外部项目引用
- `cmd/` - 程序入口

## 版本历史

- **v1.0.0** - 初始版本（单文件main.go）
- **v2.0.0** - 模块化重构（当前版本）

## 许可证

内部项目，保留所有权利。


我先给你一个项目执行流程和模块调用关系，按实际代码路径来梳理。

主执行链路：
```text
main
 ├─ 解析命令行参数
 ├─ 如果指定 -merge
 │   └─ merger.MergeCSVFiles
 │      ├─ 扫描目录下 CSV
 │      ├─ 按 up/down/total 分类
 │      ├─ mergeCSVFilesByType
 │      │   ├─ 逐个读取 CSV
 │      │   ├─ 按 fields 组合 key 聚合
 │      │   └─ merger.ExportMergedCSV
 │      └─ extractTopNPerKey
 └─ 否则进入日志分析模式
     ├─ analyzer.ParseFilterPatterns
     ├─ config.LoadFilterConfig
     ├─ config.MergeConfig
     ├─ analyzer.ParseFieldNames
     ├─ analyzer.ParseTime
     ├─ analyzer.IsFileInTimeRange
     ├─ analyzer.ProcessFilesConcurrent
     │   ├─ 多 worker 消费 tar.gz 文件
     │   ├─ analyzer.ProcessTarGz
     │   │   ├─ gzip.NewReader
     │   │   ├─ tar.NewReader
     │   │   └─ processLogFile
     │   │      ├─ findFieldPositions
     │   │      ├─ MatchFilter
     │   │      ├─ 提取统计字段
     │   │      └─ 聚合到 statsMap
     │   ├─ GenerateTempCSV（可选）
     │   └─ mergeStats
     └─ analyzer.PrintResults
         ├─ 控制台表格输出
         └─ ExportToCSV
```

模块职责图：
```text
cmd/access_log_analyzer/main.go
- 程序入口
- 负责参数解析、模式分流、串联各模块

internal/config/config.go
- 读取 config.json
- 合并命令行与配置文件参数
- 提供默认配置

internal/analyzer/parser.go
- 字段名 -> 日志列索引映射
- 文件名时间提取与时间范围判断

internal/analyzer/filter.go
- 过滤表达式解析
- 支持精确匹配和 * 通配匹配

internal/analyzer/analyzer.go
- tar.gz 解包
- txt 日志逐行扫描
- 字段抽取与过滤
- 流量/流数聚合
- 并发处理
- 结果打印与 CSV 导出

internal/merger/merger.go
- 合并已导出的 up/down/total CSV
- 二次按 fields 聚合
- 提取每组 TopN

internal/merger/exporter.go
- 合并结果导出
- 计算 Mbps、占比、汇总行

pkg/models/models.go
- TrafficStats / CSVRecord / LogFilters 数据结构

pkg/models/format.go
- 字节数格式化
```

如果你从维护角度理解，我建议重点关注这 3 条主线：
- `配置流`：`main -> LoadFilterConfig -> MergeConfig`，决定最终运行参数
- `分析流`：`main -> ProcessFilesConcurrent -> ProcessTarGz -> processLogFile -> PrintResults`
- `合并流`：`main -> MergeCSVFiles -> mergeCSVFilesByType -> ExportMergedCSV`

你可以把这个项目理解成“两阶段工具”：
- 第一阶段：从原始 `.tar.gz` 访问日志生成统计结果
- 第二阶段：把多次统计产生的 CSV 再做汇总分析

如果你要，我下一步可以继续：
1. 把这套流程整理成更正式的 Mermaid 流程图
2. 基于这张关系图，继续做一次针对当前项目的代码 review
