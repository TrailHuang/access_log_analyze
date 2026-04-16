package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// FilterConfig 过滤器配置文件结构
type FilterConfig struct {
	// 过滤参数
	SIPFilters    []string `json:"sip_filters,omitempty"`
	DIPFilters    []string `json:"dip_filters,omitempty"`
	DomainFilters []string `json:"domain_filters,omitempty"`

	// 时间过滤参数
	StartTime string `json:"start_time,omitempty"`
	EndTime   string `json:"end_time,omitempty"`

	// 统计参数
	Fields    string `json:"fields,omitempty"`
	TopN      int    `json:"top,omitempty"`
	SortBy    string `json:"sort,omitempty"`
	CsvTop    int    `json:"csv_top,omitempty"`
	Workers   int    `json:"workers,omitempty"`
	BatchSize int    `json:"batch_size,omitempty"`
	Output    string `json:"output,omitempty"`
	LogPath   string `json:"log_path,omitempty"`
}

// LoadFilterConfig 从配置文件加载过滤规则
// 配置文件是可选的，不存在时返回 nil
func LoadFilterConfig(configPath string) (*FilterConfig, error) {
	if configPath == "" {
		return nil, nil
	}

	// 检查文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// 配置文件不存在，返回 nil（不报错）
		fmt.Printf("配置文件 %s 不存在，将使用默认配置和命令行参数\n", configPath)
		return nil, nil
	}

	fmt.Println("加载配置文件:", configPath)

	// 读取文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 解析JSON
	var cfg FilterConfig
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	return &cfg, nil
}

// MergeConfig 合并配置文件和命令行参数，命令行参数优先级更高
func MergeConfig(configFile *FilterConfig, cmdFields string, cmdTopN int, cmdSortBy string, cmdCsvTop int, cmdWorkers int, cmdBatchSize int, cmdOutput string, cmdLogPath string, cmdStartTime string, cmdEndTime string, cmdSIPFilters []string, cmdDIPFilters []string, cmdDomainFilters []string) (*FilterConfig, error) {
	// 如果没有配置文件，直接返回命令行参数
	if configFile == nil {
		return &FilterConfig{
			Fields:        cmdFields,
			TopN:          cmdTopN,
			SortBy:        cmdSortBy,
			CsvTop:        cmdCsvTop,
			Workers:       cmdWorkers,
			BatchSize:     cmdBatchSize,
			Output:        cmdOutput,
			LogPath:       cmdLogPath,
			StartTime:     cmdStartTime,
			EndTime:       cmdEndTime,
			SIPFilters:    cmdSIPFilters,
			DIPFilters:    cmdDIPFilters,
			DomainFilters: cmdDomainFilters,
		}, nil
	}

	// 使用配置文件作为默认值
	merged := &FilterConfig{
		Fields:        configFile.Fields,
		TopN:          configFile.TopN,
		SortBy:        configFile.SortBy,
		CsvTop:        configFile.CsvTop,
		Workers:       configFile.Workers,
		BatchSize:     configFile.BatchSize,
		Output:        configFile.Output,
		LogPath:       configFile.LogPath,
		StartTime:     configFile.StartTime,
		EndTime:       configFile.EndTime,
		SIPFilters:    configFile.SIPFilters,
		DIPFilters:    configFile.DIPFilters,
		DomainFilters: configFile.DomainFilters,
	}

	// 命令行参数覆盖配置文件（命令行显式指定的优先）
	// fields: 如果命令行不是默认值，或者配置文件没有设置，则使用命令行
	if cmdFields != "dip,domain" || configFile.Fields == "" {
		merged.Fields = cmdFields
	}
	// topN: 如果命令行不是默认值，或者配置文件没有设置，则使用命令行
	if cmdTopN != 10 || configFile.TopN == 0 {
		merged.TopN = cmdTopN
	}
	// sortBy: 如果命令行不是默认值，或者配置文件没有设置，则使用命令行
	if cmdSortBy != "up" || configFile.SortBy == "" {
		merged.SortBy = cmdSortBy
	} else {
		// 如果命令行是默认值，使用配置文件的值
		merged.SortBy = configFile.SortBy
	}
	// csvTop: 如果命令行不是默认值，或者配置文件没有设置，则使用命令行
	if cmdCsvTop != 1000 || configFile.CsvTop == 0 {
		merged.CsvTop = cmdCsvTop
	}
	// workers: 如果命令行不是默认值，或者配置文件没有设置，则使用命令行
	if cmdWorkers != 4 || configFile.Workers == 0 {
		merged.Workers = cmdWorkers
	}
	// batchSize: 如果命令行不是默认值，或者配置文件没有设置，则使用命令行
	if cmdBatchSize != 0 || configFile.BatchSize == 0 {
		merged.BatchSize = cmdBatchSize
	}
	// output: 如果命令行有指定，或者配置文件没有设置，则使用命令行
	if cmdOutput != "" || configFile.Output == "" {
		merged.Output = cmdOutput
	}
	// logPath: 如果命令行有指定，或者配置文件没有设置，则使用命令行
	if cmdLogPath != "" || configFile.LogPath == "" {
		merged.LogPath = cmdLogPath
	}
	// startTime: 如果命令行有指定，或者配置文件没有设置，则使用命令行
	if cmdStartTime != "" || configFile.StartTime == "" {
		merged.StartTime = cmdStartTime
	}
	// endTime: 如果命令行有指定，或者配置文件没有设置，则使用命令行
	if cmdEndTime != "" || configFile.EndTime == "" {
		merged.EndTime = cmdEndTime
	}

	// 合并过滤参数（命令行和配置文件都生效）
	if len(cmdSIPFilters) > 0 {
		merged.SIPFilters = append(merged.SIPFilters, cmdSIPFilters...)
	}
	if len(cmdDIPFilters) > 0 {
		merged.DIPFilters = append(merged.DIPFilters, cmdDIPFilters...)
	}
	if len(cmdDomainFilters) > 0 {
		merged.DomainFilters = append(merged.DomainFilters, cmdDomainFilters...)
	}

	return merged, nil
}
