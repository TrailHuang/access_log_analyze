# 配置文件使用说明

## 概述

当需要配置多个参数时，使用命令行参数会不方便。此时可以使用JSON配置文件来管理所有配置。

## 使用方法

### 1. 基本使用

```bash
./access_log_analyzer -config config.json /path/to/logs
```

### 2. 配置文件与命令行参数组合使用

命令行参数优先级**高于**配置文件：

```bash
./access_log_analyzer -config config.json -top 20 /path/to/logs
```

这样会使用 `config.json` 中的所有配置，但 `top` 参数会使用命令行指定的 20。

## 配置文件格式

配置文件为JSON格式，所有字段都是可选的：

```json
{
  "fields": "sip,dip,domain",
  "top": 20,
  "sort": "down",
  "csv_top": 5000,
  "workers": 8,
  "batch_size": 100,
  "output": "result.csv",
  "log_path": "/path/to/logs",
  "start_time": "20260330000000",
  "end_time": "20260331235959",
  "sip_filters": [
    "192.168.1.100",
    "10.0.0.*"
  ],
  "dip_filters": [
    "123.180.157.193",
    "123.180.157.192"
  ],
  "domain_filters": [
    "*.example.com",
    "test.com"
  ]
}
```

### 字段说明

#### 统计参数

- `fields`: 统计字段，用逗号分隔（默认: "dip,domain"）
- `top`: 显示Top N条记录（默认: 10）
- `sort`: 排序方式：up(上行流量), down(下行流量), total(总流量)（默认: "up"）
- `csv_top`: CSV文件导出最大行数（默认: 1000, 0表示全部）
- `workers`: 并发协程数（默认: 4）
- `batch_size`: 每批处理的文件数量后生成临时CSV（默认: 0表示不生成）
- `output`: 输出CSV文件名（默认: 自动生成）
- `log_path`: 日志文件路径

#### 时间过滤参数

- `start_time`: 开始时间，格式 YYYYMMDDHHmmss（精确到秒，可选）
- `end_time`: 结束时间，格式 YYYYMMDDHHmmss（精确到秒，可选）
- 示例：`"20260330000000"` 表示2026年3月30日00:00:00
- 示例：`"20260331235959"` 表示2026年3月31日23:59:59

#### 过滤参数

- `sip_filters`: 源IP过滤列表（可选）
- `dip_filters`: 目的IP过滤列表（可选）
- `domain_filters`: 域名过滤列表（可选）

### 匹配规则

支持精确匹配和 `*` 通配符：

- `192.168.1.100` - 精确匹配该IP
- `10.0.0.*` - 匹配 10.0.0.0 ~ 10.0.0.255
- `*.example.com` - 匹配所有 example.com 的子域名

## 示例

### 示例1：完整配置

```json
{
  "fields": "sip,dip,domain",
  "top": 20,
  "sort": "down",
  "csv_top": 5000,
  "workers": 8,
  "batch_size": 100,
  "output": "result.csv",
  "sip_filters": ["192.168.1.*"],
  "dip_filters": ["123.180.157.193"],
  "domain_filters": ["*.example.com"]
}
```

使用方式：
```bash
./access_log_analyzer -config config.json
```

### 示例2：仅配置过滤条件

```json
{
  "sip_filters": ["192.168.1.100", "192.168.1.101"],
  "dip_filters": ["123.180.157.193"]
}
```

使用方式：
```bash
./access_log_analyzer -config config.json /path/to/logs
```

### 示例3：配置文件 + 命令行覆盖

配置文件 `config.json`:
```json
{
  "fields": "dip,domain",
  "top": 10,
  "sort": "up"
}
```

命令行覆盖：
```bash
./access_log_analyzer -config config.json -fields "sip,dip,domain" -top 20 -sort down /path/to/logs
```

最终使用：
- fields: "sip,dip,domain" (命令行覆盖)
- top: 20 (命令行覆盖)
- sort: "down" (命令行覆盖)

## 注意事项

1. 配置文件中的所有字段都是可选的，可以只指定需要的配置
2. **命令行参数优先级高于配置文件**（除了过滤参数会合并）
3. 过滤参数（sip_filters, dip_filters, domain_filters）会与命令行参数**合并**（取并集）
4. JSON文件必须符合标准JSON格式
5. 可以使用示例文件 `filter_config.example.json` 作为模板
6. log_path 可以通过配置文件、命令行参数或位置参数指定

