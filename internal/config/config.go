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

	// 性能分析参数
	PprofSwitch bool `json:"pprof_switch,omitempty"` // 是否开启性能分析，默认false
}

// LoadFilterConfig 从配置文件加载过滤规则
// 如果指定了config文件但不存在则失败，如果没有指定config但默认config.json不存在则使用内置配置
func LoadFilterConfig(configPath string) (*FilterConfig, error) {
	// 如果没有指定配置文件路径，使用默认的config.json
	if configPath == "" {
		configPath = "config.json"
	}

	// 检查文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// 如果是指定的配置文件不存在，则报错
		if configPath != "config.json" {
			return nil, fmt.Errorf("指定的配置文件不存在: %s", configPath)
		}
		// 如果是默认的config.json不存在，则使用内置配置
		fmt.Printf("默认配置文件 config.json 不存在，使用内置默认配置\n")
		return getDefaultConfig(), nil
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

// getDefaultConfig 返回内置默认配置
func getDefaultConfig() *FilterConfig {
	return &FilterConfig{
		Fields:        "dip,domain",
		TopN:          10,
		SortBy:        "up,down",
		CsvTop:        1000,
		Workers:       4,
		BatchSize:     0,
		Output:        "output.csv",
		LogPath:       "",
		StartTime:     "",
		EndTime:       "",
		PprofSwitch:   false,
		SIPFilters:    []string{},
		DIPFilters:    []string{},
		DomainFilters: []string{},
	}
}

// MergeConfig 合并配置文件和命令行参数，命令行参数优先级更高
func MergeConfig(configFile *FilterConfig, cmdFields string, cmdTopN int, cmdSortBy string, cmdCsvTop int, cmdWorkers int, cmdBatchSize int, cmdOutput string, cmdLogPath string, cmdStartTime string, cmdEndTime string, cmdSIPFilters []string, cmdDIPFilters []string, cmdDomainFilters []string, cmdPprofSwitch bool) (*FilterConfig, error) {
	// 如果没有配置文件，直接返回命令行参数（如果命令行参数为空，则使用内置默认值）
	if configFile == nil {
		return &FilterConfig{
			Fields:        getValueOrDefault(cmdFields, "dip,domain"),
			TopN:          getIntOrDefault(cmdTopN, 10),
			SortBy:        getValueOrDefault(cmdSortBy, "up"),
			CsvTop:        getIntOrDefault(cmdCsvTop, 1000),
			Workers:       getIntOrDefault(cmdWorkers, 4),
			BatchSize:     getIntOrDefault(cmdBatchSize, 0),
			Output:        cmdOutput,
			LogPath:       cmdLogPath,
			StartTime:     cmdStartTime,
			EndTime:       cmdEndTime,
			SIPFilters:    cmdSIPFilters,
			DIPFilters:    cmdDIPFilters,
			DomainFilters: cmdDomainFilters,
			PprofSwitch:   cmdPprofSwitch,
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
		PprofSwitch:   configFile.PprofSwitch,
	}

	// 命令行参数覆盖配置文件（命令行显式指定的优先）
	// 如果命令行参数不为空，则覆盖配置文件的值
	if cmdFields != "" {
		merged.Fields = cmdFields
	}
	if cmdTopN != 0 {
		merged.TopN = cmdTopN
	}
	if cmdSortBy != "" {
		merged.SortBy = cmdSortBy
	}
	if cmdCsvTop != 0 {
		merged.CsvTop = cmdCsvTop
	}
	if cmdWorkers != 0 {
		merged.Workers = cmdWorkers
	}
	if cmdBatchSize != 0 {
		merged.BatchSize = cmdBatchSize
	}
	if cmdOutput != "" {
		merged.Output = cmdOutput
	}
	if cmdLogPath != "" {
		merged.LogPath = cmdLogPath
	}
	if cmdStartTime != "" {
		merged.StartTime = cmdStartTime
	}
	if cmdEndTime != "" {
		merged.EndTime = cmdEndTime
	}
	if cmdPprofSwitch {
		merged.PprofSwitch = cmdPprofSwitch
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

// getValueOrDefault 如果值不为空则返回值，否则返回默认值
func getValueOrDefault(value, defaultValue string) string {
	if value != "" {
		return value
	}
	return defaultValue
}

// getIntOrDefault 如果值不为0则返回值，否则返回默认值
func getIntOrDefault(value, defaultValue int) int {
	if value != 0 {
		return value
	}
	return defaultValue
}
