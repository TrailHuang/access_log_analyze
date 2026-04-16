package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/olekukonko/tablewriter"
)

// LogFilters 日志过滤器
type LogFilters struct {
	SIPFilters    []string
	DIPFilters    []string
	DomainFilters []string
}

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

// Pool 对象池配置
var (
	// fieldValuesPool 复用 map[string]string，预分配容量30
	fieldValuesPool = sync.Pool{
		New: func() interface{} {
			return make(map[string]string, 30)
		},
	}

	// keyPartsPool 复用 []string，预分配容量20
	keyPartsPool = sync.Pool{
		New: func() interface{} {
			return make([]string, 0, 20)
		},
	}

	// keyBuilderPool 复用 strings.Builder 用于构建key
	keyBuilderPool = sync.Pool{
		New: func() interface{} {
			return &strings.Builder{}
		},
	}
)

// HasFilters 检查是否有过滤条件
func (f *LogFilters) HasFilters() bool {
	return len(f.SIPFilters) > 0 || len(f.DIPFilters) > 0 || len(f.DomainFilters) > 0
}

// MatchFilter 检查值是否匹配过滤条件
func MatchFilter(value string, filters []string) bool {
	if len(filters) == 0 {
		return true // 没有过滤条件,默认匹配
	}

	for _, pattern := range filters {
		if matchPattern(value, pattern) {
			return true
		}
	}
	return false
}

// matchPattern 匹配单个模式,支持*通配符
func matchPattern(value, pattern string) bool {
	// 如果没有*,完全匹配
	if !strings.Contains(pattern, "*") {
		return value == pattern
	}

	// 将*转换为正则表达式
	regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
	regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")

	matched, err := regexp.MatchString(regexPattern, value)
	if err != nil {
		return false
	}
	return matched
}

// parseFilterPatterns 解析过滤模式
func parseFilterPatterns(filterStr string) []string {
	if filterStr == "" {
		return []string{}
	}

	patterns := strings.Split(filterStr, ",")
	result := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// extractTimeFromFileName 从文件名中提取时间信息
// 支持格式：log_20260331_success.tar.gz 或 access_log_20260330062627638743.tar.gz
// 提取后统一补齐到秒精度（14位：YYYYMMDDHHmmss）
func extractTimeFromFileName(fileName string) string {
	// 去除扩展名
	baseName := strings.TrimSuffix(fileName, ".tar.gz")
	baseName = strings.TrimSuffix(baseName, ".gz")

	// 使用正则表达式匹配所有8位或更多数字的序列
	re := regexp.MustCompile(`\d{8,}`)
	matches := re.FindAllString(baseName, -1)

	if len(matches) == 0 {
		return ""
	}

	// 选择最长的数字串作为时间（时间戳通常是最长的数字串）
	timeStr := matches[0]
	for _, match := range matches {
		if len(match) > len(timeStr) {
			timeStr = match
		}
	}

	// 将时间字符串处理到14位（秒精度）
	// YYYYMMDDHHmmss... -> 截断到秒（14位）
	if len(timeStr) >= 14 {
		return timeStr[:14]
	}
	// 如果不足14位，说明不是有效的时间格式
	return ""
}

// parseTime 解析时间字符串为int64，必须是14位秒精度（YYYYMMDDHHmmss）
func parseTime(timeStr string) (int64, error) {
	if timeStr == "" {
		return 0, nil
	}

	// 移除可能的空格
	timeStr = strings.TrimSpace(timeStr)

	// 验证格式：必须是14位数字
	if len(timeStr) != 14 {
		return 0, fmt.Errorf("无效的时间格式: %s (必须为14位，格式: YYYYMMDDHHmmss，例如: 20260330062627)", timeStr)
	}

	// 转换为整数
	t, err := strconv.ParseInt(timeStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("无效的时间格式: %s", timeStr)
	}

	return t, nil
}

// isFileInTimeRange 检查文件是否在时间范围内
// startTime和endTime都应该是12位分钟精度
func isFileInTimeRange(fileName string, startTime int64, endTime int64) bool {
	// 从文件名提取时间（已经是12位分钟精度）
	fileTimeStr := extractTimeFromFileName(fileName)
	if fileTimeStr == "" {
		// 无法提取时间，不过滤
		return true
	}
	fileTime, err := parseTime(fileTimeStr)
	if err != nil {
		// 解析失败，不过滤
		return true
	}

	// 检查时间范围（都是12位分钟精度，直接比较）
	if startTime > 0 && fileTime < startTime {
		return false
	}
	if endTime > 0 && fileTime > endTime {
		return false
	}

	return true
}

// loadFilterConfig 从配置文件加载过滤规则
// 配置文件是可选的，不存在时返回 nil
func loadFilterConfig(configPath string) (*FilterConfig, error) {
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
	var config FilterConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	return &config, nil
}

// mergeConfig 合并配置文件和命令行参数，命令行参数优先级更高
func mergeConfig(configFile *FilterConfig, cmdFields string, cmdTopN int, cmdSortBy string, cmdCsvTop int, cmdWorkers int, cmdBatchSize int, cmdOutput string, cmdLogPath string, cmdStartTime string, cmdEndTime string, cmdSIPFilters []string, cmdDIPFilters []string, cmdDomainFilters []string) (*FilterConfig, error) {
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
	// 注意：由于Go flag包的特性，我们无法区分用户是否显式指定了参数
	// 所以我们采用这样的策略：如果命令行参数与默认值不同，则使用命令行参数
	// 如果命令行参数是默认值，则使用配置文件的值（如果配置文件有设置）

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

// TrafficStats 存储流量统计数据
type TrafficStats struct {
	Key       string            // 统计key (由指定字段组合)
	Fields    map[string]string // 各字段的值
	UpTotal   int64
	DownTotal int64
	FlowTotal int64
}

func main() {
	// 定义命令行参数
	fields := flag.String("fields", "dip,domain", "统计字段,用逗号分隔。支持的字段: house_id, sip, dip, proto, sport, dport, domain, url, duration, utc_time, title, app_proto, biz_proto, referer, location, content, data_size, up_traffic, down_traffic, app_name")
	topN := flag.Int("top", 10, "显示Top N条记录")
	sortBy := flag.String("sort", "up", "排序方式: up(上行流量), down(下行流量), total(总流量)，支持逗号分隔多个值")
	csvTop := flag.Int("csv_top", 1000, "CSV文件导出最大行数(默认1000, 0表示全部)")
	workers := flag.Int("workers", 4, "并发协程数(默认4)")
	batchSize := flag.Int("batch_size", 0, "每批处理的文件数量后生成临时CSV(默认0表示不生成)")
	output := flag.String("output", "", "输出CSV文件名(默认自动生成)")
	logPath := flag.String("log_path", "", "日志文件路径(目录或tar.gz文件)")
	mergeDir := flag.String("merge", "", "合并目录: 将目录下所有up/down/total CSV文件按fields合并汇总")

	// 过滤参数
	sipFilter := flag.String("sip", "", "源IP过滤,支持逗号分隔多个值,支持*模糊匹配")
	dipFilter := flag.String("dip", "", "目的IP过滤,支持逗号分隔多个值,支持*模糊匹配")
	domainFilter := flag.String("domain", "", "域名过滤,支持逗号分隔多个值,支持*模糊匹配")
	startTime := flag.String("start", "", "开始时间(格式: YYYYMMDDHHmmss，精确到秒)")
	endTime := flag.String("end", "", "结束时间(格式: YYYYMMDDHHmmss，精确到秒)")
	configFile := flag.String("config", "config.json", "过滤器配置文件路径(JSON格式，可选)")

	flag.Parse()

	// 如果是merge模式，直接处理并退出
	if *mergeDir != "" {
		err := mergeCSVFiles(*mergeDir, *fields, *topN)
		if err != nil {
			fmt.Printf("错误: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 性能分析: CPU profile
	cpuProfile, err := os.Create("cpu_profile.prof")
	if err != nil {
		fmt.Printf("创建CPU profile文件失败: %v\n", err)
		return
	}
	pprof.StartCPUProfile(cpuProfile)
	defer pprof.StopCPUProfile()

	// 性能分析: 内存 profile
	defer func() {
		memProfile, err := os.Create("mem_profile.prof")
		if err != nil {
			fmt.Printf("创建内存profile文件失败: %v\n", err)
			return
		}
		pprof.WriteHeapProfile(memProfile)
		memProfile.Close()
	}()

	// 验证排序参数
	if *sortBy != "up" && *sortBy != "down" && *sortBy != "total" {
		fmt.Printf("错误: 无效的排序方式: %s (支持: up, down, total)\n", *sortBy)
		os.Exit(1)
	}

	// 验证协程数
	if *workers <= 0 {
		fmt.Printf("错误: 协程数必须大于0\n")
		os.Exit(1)
	}

	// 获取日志路径
	dirPath := *logPath
	if dirPath == "" {
		if flag.NArg() < 1 {
			fmt.Println("用法: go run main.go [选项] <目录路径>")
			fmt.Println("      go run main.go -log_path <路径> [选项]")
			printHelp()
			os.Exit(1)
		}
		dirPath = flag.Arg(0)
	}

	// 解析命令行过滤器
	cmdSIPFilters := parseFilterPatterns(*sipFilter)
	cmdDIPFilters := parseFilterPatterns(*dipFilter)
	cmdDomainFilters := parseFilterPatterns(*domainFilter)

	// 加载配置文件
	filterConfig, err := loadFilterConfig(*configFile)
	if err != nil {
		fmt.Printf("错误: %v\n", err)
		os.Exit(1)
	}

	// 合并配置（命令行优先级高于配置文件）
	mergedConfig, err := mergeConfig(filterConfig, *fields, *topN, *sortBy, *csvTop, *workers, *batchSize, *output, dirPath, *startTime, *endTime, cmdSIPFilters, cmdDIPFilters, cmdDomainFilters)
	if err != nil {
		fmt.Printf("错误: 合并配置失败: %v\n", err)
		os.Exit(1)
	}

	// 使用合并后的配置更新参数
	*fields = mergedConfig.Fields
	*topN = mergedConfig.TopN
	*sortBy = mergedConfig.SortBy
	*csvTop = mergedConfig.CsvTop
	*workers = mergedConfig.Workers
	*batchSize = mergedConfig.BatchSize
	if mergedConfig.Output != "" {
		*output = mergedConfig.Output
	}
	dirPath = mergedConfig.LogPath

	// 创建过滤器
	filters := &LogFilters{
		SIPFilters:    mergedConfig.SIPFilters,
		DIPFilters:    mergedConfig.DIPFilters,
		DomainFilters: mergedConfig.DomainFilters,
	}

	// 检查目录是否存在
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		fmt.Printf("错误: 路径不存在: %s\n", dirPath)
		os.Exit(1)
	}

	// 解析字段名到索引的映射
	fieldIndexes, err := parseFieldNames(*fields)
	if err != nil {
		fmt.Printf("错误: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("开始分析: %s\n", dirPath)
	fmt.Printf("统计字段: %s\n", *fields)
	fmt.Printf("显示Top: %d\n", *topN)

	//sortLabel := map[string]string{"up": "上行流量", "down": "下行流量", "total": "总流量"}
	fmt.Printf("排序方式: %s\n", *sortBy)
	fmt.Printf("并发协程: %d\n", *workers)
	if *configFile != "" {
		fmt.Printf("配置文件: %s\n", *configFile)
	}
	if filters.HasFilters() {
		fmt.Printf("过滤条件:\n")
		if len(filters.SIPFilters) > 0 {
			fmt.Printf("  源IP: %v\n", filters.SIPFilters)
		}
		if len(filters.DIPFilters) > 0 {
			fmt.Printf("  目的IP: %v\n", filters.DIPFilters)
		}
		if len(filters.DomainFilters) > 0 {
			fmt.Printf("  域名: %v\n", filters.DomainFilters)
		}
	}
	if mergedConfig.StartTime != "" || mergedConfig.EndTime != "" {
		fmt.Printf("时间范围:\n")
		if mergedConfig.StartTime != "" {
			fmt.Printf("  开始时间: %s\n", mergedConfig.StartTime)
		}
		if mergedConfig.EndTime != "" {
			fmt.Printf("  结束时间: %s\n", mergedConfig.EndTime)
		}
	}

	// 解析时间范围
	startTimeInt, err := parseTime(mergedConfig.StartTime)
	if err != nil {
		fmt.Printf("错误: 解析开始时间失败: %v\n", err)
		startTimeInt = 0
	}
	endTimeInt, err := parseTime(mergedConfig.EndTime)
	if err != nil {
		fmt.Printf("错误: 解析结束时间失败: %v\n", err)
		endTimeInt = 0
	}

	// 查找所有tar.gz文件
	var tarGzFiles []string
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		// 跳过目录
		if info.IsDir() {
			return nil
		}

		// 只处理tar.gz文件
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".tar.gz") {
			return nil
		}

		// 时间过滤
		if !isFileInTimeRange(info.Name(), startTimeInt, endTimeInt) {
			return nil
		}

		tarGzFiles = append(tarGzFiles, path)
		return nil
	})

	if err != nil {
		fmt.Printf("错误: 遍历目录时出错: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("找到 %d 个tar.gz文件\n", len(tarGzFiles))

	// 并发处理文件
	statsMap := processFilesConcurrent(tarGzFiles, fieldIndexes, filters, *workers, *batchSize, *output)

	// 输出统计结果
	printResults(statsMap, fieldIndexes, *topN, *sortBy, *csvTop, *output)
}

// processFilesConcurrent 并发处理多个tar.gz文件
func processFilesConcurrent(files []string, fieldIndexes map[string]int, filters *LogFilters, numWorkers int, batchSize int, outputBaseName string) map[string]*TrafficStats {
	// 限制最大协程数不超过文件数
	if numWorkers > len(files) {
		numWorkers = len(files)
	}

	if numWorkers == 0 {
		return make(map[string]*TrafficStats)
	}

	fmt.Printf("使用 %d 个协程并发处理，每 %d 个文件生成一次临时CSV\n", numWorkers, batchSize)

	// 创建任务通道
	taskCh := make(chan string, len(files))
	for _, file := range files {
		taskCh <- file
	}
	close(taskCh)

	// 结果通道
	type result struct {
		stats map[string]*TrafficStats
		err   error
	}
	resultCh := make(chan result, len(files))

	// 启动工作协程
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// 每个协程独立累积统计
			localStats := make(map[string]*TrafficStats)
			fileCount := 0

			for filePath := range taskCh {
				fileCount++

				// 记录单文件处理时间
				fileStart := time.Now()
				fileName := filepath.Base(filePath)

				err := processTarGz(filePath, localStats, fieldIndexes, filters)

				// 计算处理时间
				fileDuration := time.Since(fileStart)

				if err != nil {
					fmt.Printf("  [Worker %d] 警告: 处理文件 %s 时出错: %v (%.2fs)\n", workerID, fileName, err, fileDuration.Seconds())
				} else {
					fmt.Printf("  [Worker %d] ✓ %s 处理完成 (%.2fs)\n", workerID, fileName, fileDuration.Seconds())
				}

				// 检查是否达到batchSize，如果是则生成临时CSV（不重置统计，继续累积）
				if batchSize > 0 && fileCount%batchSize == 0 {
					generateTempCSV(localStats, fieldIndexes, outputBaseName, workerID, fileCount)
				}

				// 发送结果（仅用于进度显示，不传递统计数据避免并发问题）
				resultCh <- result{stats: nil, err: err}
			}

			// 处理完成后，发送完整的统计结果
			if len(localStats) > 0 {
				// 如果启用了batch_size，生成最终CSV
				if batchSize > 0 {
					generateTempCSV(localStats, fieldIndexes, outputBaseName, workerID, fileCount)
				}

				// 创建localStats的副本用于发送，避免并发访问问题
				statsCopy := make(map[string]*TrafficStats, len(localStats))
				for key, stats := range localStats {
					// 创建TrafficStats的副本
					fieldValuesCopy := make(map[string]string, len(stats.Fields))
					for k, v := range stats.Fields {
						fieldValuesCopy[k] = v
					}
					statsCopy[key] = &TrafficStats{
						Key:       stats.Key,
						Fields:    fieldValuesCopy,
						UpTotal:   stats.UpTotal,
						DownTotal: stats.DownTotal,
						FlowTotal: stats.FlowTotal,
					}
				}

				// 发送最终统计结果副本
				resultCh <- result{stats: statsCopy, err: nil}
			}
		}(i)
	}

	// 关闭结果通道(等待所有worker完成)
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// 汇总结果
	finalStats := make(map[string]*TrafficStats)
	processedFiles := 0

	for res := range resultCh {
		processedFiles++
		if res.stats != nil {
			// 合并统计结果
			mergeStats(finalStats, res.stats)
		}

		// 显示进度
		if processedFiles%10 == 0 || processedFiles == len(files) {
			fmt.Printf("\r已处理: %d/%d 文件", processedFiles, len(files))
		}
	}
	fmt.Println()

	return finalStats
}

// mergeStats 合并统计结果(将src合并到dst)
func mergeStats(dst, src map[string]*TrafficStats) {
	for key, srcStats := range src {
		if dstStats, exists := dst[key]; exists {
			// key已存在,累加流量
			dstStats.UpTotal += srcStats.UpTotal
			dstStats.DownTotal += srcStats.DownTotal
			dstStats.FlowTotal += srcStats.FlowTotal
		} else {
			// key不存在,直接复制
			dst[key] = &TrafficStats{
				Key:       srcStats.Key,
				Fields:    srcStats.Fields,
				UpTotal:   srcStats.UpTotal,
				DownTotal: srcStats.DownTotal,
				FlowTotal: srcStats.FlowTotal,
			}
		}
	}
}

// generateTempCSV 生成临时CSV文件
func generateTempCSV(statsMap map[string]*TrafficStats, fieldIndexes map[string]int, outputBaseName string, workerID int, fileCount int) {
	if len(statsMap) == 0 {
		return
	}

	// 生成临时文件名：test_worker0_1-100.csv, test_worker0_1-200.csv, ...
	var tempFileName string
	if outputBaseName == "" {
		tempFileName = fmt.Sprintf("traffic_stats_worker%d_1-%d.csv", workerID, fileCount)
	} else {
		// 去除扩展名，添加后缀
		baseName := strings.TrimSuffix(outputBaseName, filepath.Ext(outputBaseName))
		ext := filepath.Ext(outputBaseName)
		if ext == "" {
			ext = ".csv"
		}
		tempFileName = fmt.Sprintf("%s_worker%d_1-%d%s", baseName, workerID, fileCount, ext)
	}

	// 转换为切片以便排序
	statsList := make([]*TrafficStats, 0, len(statsMap))
	for _, stats := range statsMap {
		statsList = append(statsList, stats)
	}

	// 按总流量降序排序
	sort.Slice(statsList, func(i, j int) bool {
		return (statsList[i].UpTotal + statsList[i].DownTotal) > (statsList[j].UpTotal + statsList[j].DownTotal)
	})

	// 按字段索引排序，保证输出顺序一致
	type fieldPair struct {
		name string
		idx  int
	}
	sortedFields := make([]fieldPair, 0, len(fieldIndexes))
	for name, idx := range fieldIndexes {
		sortedFields = append(sortedFields, fieldPair{name, idx})
	}
	sort.Slice(sortedFields, func(i, j int) bool {
		return sortedFields[i].idx < sortedFields[j].idx
	})

	// 导出CSV
	file, err := os.Create(tempFileName)
	if err != nil {
		fmt.Printf("\n  [Worker %d] 错误: 创建临时CSV文件失败 %s: %v\n", workerID, tempFileName, err)
		return
	}
	defer file.Close()

	// 写入BOM标记,使Excel能正确识别UTF-8
	file.WriteString("\xEF\xBB\xBF")

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	writer.WriteString("排名")
	for _, fp := range sortedFields {
		writer.WriteString("," + fp.name)
	}
	writer.WriteString(",上行流量(字节),上行流量,下行流量(字节),下行流量,总流量(字节),总流量,流数\n")

	// 写入数据
	for i, stats := range statsList {
		writer.WriteString(fmt.Sprintf("%d", i+1))
		for _, fp := range sortedFields {
			// 处理包含逗号的字段值,用引号包裹
			value := stats.Fields[fp.name]
			if strings.Contains(value, ",") || strings.Contains(value, "\"") {
				value = "\"" + strings.ReplaceAll(value, "\"", "\"\"") + "\""
			}
			writer.WriteString("," + value)
		}
		writer.WriteString(fmt.Sprintf(",%d,%s,%d,%s,%d,%s,%d\n",
			stats.UpTotal,
			formatBytes(stats.UpTotal),
			stats.DownTotal,
			formatBytes(stats.DownTotal),
			stats.UpTotal+stats.DownTotal,
			formatBytes(stats.UpTotal+stats.DownTotal),
			stats.FlowTotal,
		))
	}

	fmt.Printf("  [Worker %d] ✓ 临时CSV已生成: %s (已处理 %d 个文件, %d 条记录)\n", workerID, tempFileName, fileCount, len(statsList))
}

// parseFieldNames 解析字段名到索引的映射
func parseFieldNames(fieldsStr string) (map[string]int, error) {
	// 字段名到索引的映射 (21个字段)
	fieldMap := map[string]int{
		"house_id":     0,
		"sip":          1,
		"dip":          2,
		"proto":        3,
		"sport":        4,
		"dport":        5,
		"domain":       6,
		"url":          7,
		"duration":     8,
		"utc_time":     9,
		"title":        10,
		"app_proto":    11,
		"biz_proto":    12,
		"referer":      13,
		"location":     14,
		"content":      15,
		"data_size":    16,
		"up_traffic":   18,
		"down_traffic": 19,
		"app_name":     20,
	}

	fields := strings.Split(fieldsStr, ",")
	result := make(map[string]int)

	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if idx, ok := fieldMap[field]; ok {
			result[field] = idx
		} else {
			return nil, fmt.Errorf("不支持的字段: %s", field)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("至少需要指定一个统计字段")
	}

	return result, nil
}

// processTarGz 处理单个tar.gz文件
func processTarGz(filePath string, statsMap map[string]*TrafficStats, fieldIndexes map[string]int, filters *LogFilters) error {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	// 创建gzip reader
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("创建gzip reader失败: %w", err)
	}
	defer gzReader.Close()

	// 创建tar reader
	tarReader := tar.NewReader(gzReader)

	// 遍历tar包中的所有文件
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取tar文件失败: %w", err)
		}

		// 只处理txt文件
		if header.Typeflag == tar.TypeReg && strings.HasSuffix(strings.ToLower(header.Name), ".txt") {
			err = processLogFile(tarReader, statsMap, fieldIndexes, filters)
			if err != nil {
				return fmt.Errorf("处理日志文件 %s 失败: %w", header.Name, err)
			}
		}
	}

	return nil
}

// processLogFile 解析日志文件并统计流量
func processLogFile(reader io.Reader, statsMap map[string]*TrafficStats, fieldIndexes map[string]int, filters *LogFilters) error {
	scanner := bufio.NewScanner(reader)
	// 增加buffer大小以处理长行
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	// 优化2: 字段排序只做一次 - 在循环外预排序字段
	type fieldPair struct {
		name string
		idx  int
	}
	sortedFields := make([]fieldPair, 0, len(fieldIndexes))
	for name, idx := range fieldIndexes {
		sortedFields = append(sortedFields, fieldPair{name, idx})
	}
	// 按索引排序
	sort.Slice(sortedFields, func(i, j int) bool {
		return sortedFields[i].idx < sortedFields[j].idx
	})

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// 跳过空行
		if strings.TrimSpace(line) == "" {
			continue
		}

		// 优化1: 使用strings.Split替代csv.Reader，避免每行创建新对象
		// 日志格式使用|作为分隔符，没有引号转义，可以直接用Split
		fields := strings.Split(line, "|")

		// 日志格式: HouseId|源IP|目的IP|协议类型|源端口|目的端口|域名|URL|Duration|UTC时间|Title|应用层协议|业务层协议|Referer|Location|网站内容|访问数据量|上行流量|下行流量|应用名称
		// 字段索引: 0       1     2      3       4      5      6    7   8        9        10    11         12         13      14       15       16        17      18      19
		// 实际数据: 16|175.8.116.202|123.180.157.193|1|16979|443|||48|1776150396||1|8|28||||0|0|123665|

		if len(fields) < 20 {
			fmt.Printf("  警告: 第 %d 行字段数不足 (%d < 20)\n", lineNum, len(fields))
			continue
		}

		// 优化3: 使用sync.Pool复用对象，减少GC压力
		// 从Pool获取对象
		keyParts := keyPartsPool.Get().([]string)
		keyParts = keyParts[:0] // 重置长度，保留容量

		fieldValues := fieldValuesPool.Get().(map[string]string)
		// 清空map - 遍历delete方式
		for k := range fieldValues {
			delete(fieldValues, k)
		}

		// 按排序后的顺序提取
		for _, fp := range sortedFields {
			value := strings.TrimSpace(fields[fp.idx])
			if value == "" {
				value = "-"
			}
			keyParts = append(keyParts, value)
			fieldValues[fp.name] = value
		}

		// 提取过滤需要的字段(如果不在统计字段中)
		if len(filters.SIPFilters) > 0 && fieldValues["sip"] == "" {
			value := strings.TrimSpace(fields[1])
			if value == "" {
				value = "-"
			}
			fieldValues["sip"] = value
		}
		if len(filters.DIPFilters) > 0 && fieldValues["dip"] == "" {
			value := strings.TrimSpace(fields[2])
			if value == "" {
				value = "-"
			}
			fieldValues["dip"] = value
		}
		if len(filters.DomainFilters) > 0 && fieldValues["domain"] == "" {
			value := strings.TrimSpace(fields[6])
			if value == "" {
				value = "-"
			}
			fieldValues["domain"] = value
		}

		// 提取流量字段用于统计(如果不在统计字段中)
		if fieldValues["up_traffic"] == "" {
			value := strings.TrimSpace(fields[18])
			if value == "" {
				value = "0"
			}
			fieldValues["up_traffic"] = value
		}
		if fieldValues["down_traffic"] == "" {
			value := strings.TrimSpace(fields[19])
			if value == "" {
				value = "0"
			}
			fieldValues["down_traffic"] = value
		}

		// 优化4: 使用strings.Builder复用对象构建key，减少分配
		keyBuilder := keyBuilderPool.Get().(*strings.Builder)
		keyBuilder.Reset()

		// 预计算key长度并预分配容量
		totalLen := 0
		for i, part := range keyParts {
			totalLen += len(part)
			if i < len(keyParts)-1 {
				totalLen++ // 分隔符 |
			}
		}
		keyBuilder.Grow(totalLen)

		// 构建key
		for i, part := range keyParts {
			if i > 0 {
				keyBuilder.WriteByte('|')
			}
			keyBuilder.WriteString(part)
		}
		key := keyBuilder.String()

		// 将builder放回Pool
		keyBuilderPool.Put(keyBuilder)

		// 应用过滤条件
		sip := fieldValues["sip"]
		dip := fieldValues["dip"]
		domain := fieldValues["domain"]

		if !MatchFilter(sip, filters.SIPFilters) {
			// 过滤不匹配，归还Pool对象
			keyPartsPool.Put(keyParts)
			fieldValuesPool.Put(fieldValues)
			continue
		}
		if !MatchFilter(dip, filters.DIPFilters) {
			// 过滤不匹配，归还Pool对象
			keyPartsPool.Put(keyParts)
			fieldValuesPool.Put(fieldValues)
			continue
		}
		if !MatchFilter(domain, filters.DomainFilters) {
			// 过滤不匹配，归还Pool对象
			keyPartsPool.Put(keyParts)
			fieldValuesPool.Put(fieldValues)
			continue
		}

		// 提取上行流量 (索引18) 和 下行流量 (索引19)
		// 从实际日志看: ...|0|0|123665| 最后三个字段是 data_size(17)|up(18)|down(19)|app_name(20空)
		upTraffic, err := strconv.ParseInt(strings.TrimSpace(fields[18]), 10, 64)
		if err != nil {
			// 如果解析失败,尝试处理空值或其他格式
			if strings.TrimSpace(fields[18]) != "" {
				fmt.Printf("  警告: 第 %d 行上行流量解析失败: %v\n", lineNum, err)
			}
			upTraffic = 0
		}

		downTraffic, err := strconv.ParseInt(strings.TrimSpace(fields[19]), 10, 64)
		if err != nil {
			if strings.TrimSpace(fields[19]) != "" {
				fmt.Printf("  警告: 第 %d 行下行流量解析失败: %v\n", lineNum, err)
			}
			downTraffic = 0
		}

		// 更新统计
		if stats, exists := statsMap[key]; exists {
			stats.UpTotal += upTraffic
			stats.DownTotal += downTraffic
			stats.FlowTotal++
			// key已存在，归还Pool对象（因为fieldValues不会被使用）
			keyPartsPool.Put(keyParts)
			fieldValuesPool.Put(fieldValues)
		} else {
			// key不存在，需要复制fieldValues到新的map（因为Pool对象会被复用）
			// 预分配容量避免rehash
			fieldValuesCopy := make(map[string]string, len(fieldValues))
			for k, v := range fieldValues {
				fieldValuesCopy[k] = v
			}
			statsMap[key] = &TrafficStats{
				Key:       key,
				Fields:    fieldValuesCopy,
				UpTotal:   upTraffic,
				DownTotal: downTraffic,
				FlowTotal: 1,
			}
			// 归还Pool对象
			keyPartsPool.Put(keyParts)
			fieldValuesPool.Put(fieldValues)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取文件时出错: %w", err)
	}

	return nil
}

// printResults 输出统计结果
func printResults(statsMap map[string]*TrafficStats, fieldIndexes map[string]int, topN int, sortBy string, csvTop int, outputFile string) {

	// 转换为切片以便排序
	statsList := make([]*TrafficStats, 0, len(statsMap))
	for _, stats := range statsMap {
		statsList = append(statsList, stats)
	}

	// 解析排序方式，支持逗号分隔的多个排序维度
	sortTypes := strings.Split(sortBy, ",")
	for i, st := range sortTypes {
		sortTypes[i] = strings.TrimSpace(st)
	}
	// 去重
	seen := make(map[string]bool)
	uniqueSortTypes := []string{}
	for _, st := range sortTypes {
		if !seen[st] {
			seen[st] = true
			uniqueSortTypes = append(uniqueSortTypes, st)
		}
	}
	sortTypes = uniqueSortTypes

	// 对每个排序维度生成结果
	for _, sortType := range sortTypes {
		// 创建副本进行排序
		sortedList := make([]*TrafficStats, len(statsList))
		copy(sortedList, statsList)

		// 按指定方式排序
		sort.Slice(sortedList, func(i, j int) bool {
			switch sortType {
			case "down":
				return sortedList[i].DownTotal > sortedList[j].DownTotal
			case "total":
				return (sortedList[i].UpTotal + sortedList[i].DownTotal) > (sortedList[j].UpTotal + sortedList[j].DownTotal)
			default: // up
				return sortedList[i].UpTotal > sortedList[j].UpTotal
			}
		})

		// 确定显示数量
		displayCount := topN
		if len(sortedList) < displayCount {
			displayCount = len(sortedList)
		}

		// 按字段索引排序，保证输出顺序一致
		type fieldPair struct {
			name string
			idx  int
		}
		sortedFields := make([]fieldPair, 0, len(fieldIndexes))
		for name, idx := range fieldIndexes {
			sortedFields = append(sortedFields, fieldPair{name, idx})
		}
		sort.Slice(sortedFields, func(i, j int) bool {
			return sortedFields[i].idx < sortedFields[j].idx
		})

		// 打印排序类型标题
		sortLabel := map[string]string{"up": "上行流量", "down": "下行流量", "total": "总流量"}
		label := sortLabel[sortType]
		if label == "" {
			label = sortType
		}
		fmt.Printf("\n========== 按%s排序 ==========\n", label)

		// 创建表格
		headers := []string{"排名"}
		for _, fp := range sortedFields {
			headers = append(headers, fp.name)
		}
		headers = append(headers, "上行流量\n(字节)", "上行流量\n", "下行流量\n(字节)", "下行流量\n", "总流量\n(字节)", "总流量\n", "流数\n")

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader(headers)
		table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
		table.SetCenterSeparator("|")
		table.SetColumnSeparator("|")
		table.SetRowSeparator("-")
		table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetHeaderLine(true)
		table.SetAutoWrapText(false)

		// 输出数据
		totalUp := int64(0)
		totalDown := int64(0)
		totalFlow := int64(0)

		for i := 0; i < displayCount; i++ {
			stats := sortedList[i]

			row := []string{fmt.Sprintf("%d", i+1)}
			for _, fp := range sortedFields {
				row = append(row, stats.Fields[fp.name])
			}

			totalBytes := stats.UpTotal + stats.DownTotal
			row = append(row,
				fmt.Sprintf("%d", stats.UpTotal),
				formatBytes(stats.UpTotal),
				fmt.Sprintf("%d", stats.DownTotal),
				formatBytes(stats.DownTotal),
				fmt.Sprintf("%d", totalBytes),
				formatBytes(totalBytes),
				fmt.Sprintf("%d", stats.FlowTotal),
			)

			table.Append(row)
			totalUp += stats.UpTotal
			totalDown += stats.DownTotal
			totalFlow += stats.FlowTotal
		}

		// 添加总计行
		totalAll := totalUp + totalDown
		totalRow := []string{"总计"}
		for i := 0; i < len(fieldIndexes); i++ {
			totalRow = append(totalRow, "")
		}
		totalRow = append(totalRow,
			fmt.Sprintf("%d", totalUp),
			formatBytes(totalUp),
			fmt.Sprintf("%d", totalDown),
			formatBytes(totalDown),
			fmt.Sprintf("%d", totalAll),
			formatBytes(totalAll),
			fmt.Sprintf("%d", totalFlow),
		)
		table.Append(totalRow)

		// 渲染表格
		fmt.Println()
		table.Render()
		fmt.Printf("\n共 %d 个唯一组合, 显示 Top %d\n", len(statsMap), displayCount)

		// 导出CSV（为每个排序维度生成独立文件）
		exportToCSV(sortedList, fieldIndexes, csvTop, outputFile, sortType)
	}
}

// printHelp 打印帮助信息
func printHelp() {
	fmt.Println("")
	fmt.Println("支持的字段:")
	fmt.Println("  house_id   - HouseId")
	fmt.Println("  sip        - 源IP")
	fmt.Println("  dip        - 目的IP")
	fmt.Println("  proto      - 协议类型")
	fmt.Println("  sport      - 源端口")
	fmt.Println("  dport      - 目的端口")
	fmt.Println("  domain     - 域名")
	fmt.Println("  url        - URL")
	fmt.Println("  duration   - Duration")
	fmt.Println("  utc_time   - UTC时间")
	fmt.Println("  title      - Title")
	fmt.Println("  app_proto  - 应用层协议")
	fmt.Println("  biz_proto  - 业务层协议")
	fmt.Println("  referer    - Referer")
	fmt.Println("  location   - Location")
	fmt.Println("  content    - 网站内容")
	fmt.Println("  data_size  - 访问数据量")
	fmt.Println("  up_traffic - 上行流量")
	fmt.Println("  down_traffic - 下行流量")
	fmt.Println("  app_name   - 应用名称")
	fmt.Println("")
	fmt.Println("过滤参数:")
	fmt.Println("  -sip       源IP过滤,支持逗号分隔多个值,支持*模糊匹配")
	fmt.Println("  -dip       目的IP过滤,支持逗号分隔多个值,支持*模糊匹配")
	fmt.Println("  -domain    域名过滤,支持逗号分隔多个值,支持*模糊匹配")
	fmt.Println("  -config    过滤器配置文件路径(JSON格式),可与命令行参数组合使用")
	fmt.Println("")
	fmt.Println("时间过滤:")
	fmt.Println("  -start     开始时间(格式: YYYYMMDDHHmmss，精确到秒)")
	fmt.Println("  -end       结束时间(格式: YYYYMMDDHHmmss，精确到秒)")
	fmt.Println("  示例: -start 20260330000000 -end 20260331235959")
	fmt.Println("  说明: 20260330000000表示2026年3月30日00:00:00")
	fmt.Println("        20260331235959表示2026年3月31日23:59:59")
	fmt.Println("")
	fmt.Println("配置文件格式 (JSON):")
	fmt.Println("  {")
	fmt.Println("    \"sip_filters\": [\"192.168.1.100\", \"10.0.0.*\"],")
	fmt.Println("    \"dip_filters\": [\"123.180.157.193\", \"123.180.157.192\"],")
	fmt.Println("    \"domain_filters\": [\"*.example.com\", \"test.com\"],")
	fmt.Println("    \"start_time\": \"20260330000000\",")
	fmt.Println("    \"end_time\": \"20260331235959\"")
	fmt.Println("  }")
	fmt.Println("  示例文件: filter_config.example.json")
	fmt.Println("")
	fmt.Println("排序参数:")
	fmt.Println("  -sort      排序方式: up(上行流量), down(下行流量), total(总流量)")
	fmt.Println("           支持逗号分隔多个值,为每个排序方式生成独立的表格和CSV文件")
	fmt.Println("           示例: -sort \"up,down,total\" 或 -sort up")
	fmt.Println("           CSV文件名会自动添加后缀: result_up.csv, result_down.csv, result_total.csv")
	fmt.Println("")
	fmt.Println("示例:")
	fmt.Println("  go run main.go /path/to/logs")
	fmt.Println("  go run main.go -log_path /path/to/logs -top 20")
	fmt.Println("  go run main.go -fields \"sip,dip,domain\" -top 5 /path/to/logs")
	fmt.Println("  go run main.go -sip 192.168.1.100 -dip 10.0.0.* /path/to/logs")
	fmt.Println("  go run main.go -domain \"*.example.com,test.com\" /path/to/logs")
	fmt.Println("  go run main.go -config filter_config.json /path/to/logs")
	fmt.Println("  go run main.go -config filter_config.json -sip 1.2.3.4 /path/to/logs  # 合并使用")
	fmt.Println("  go run main.go -start 20260330000000 -end 20260331235959 /path/to/logs")
	fmt.Println("  go run main.go -start 20260330062627 /path/to/logs")
	fmt.Println("  go run main.go -sort down -top 20 /path/to/logs")
	fmt.Println("  go run main.go -sort total /path/to/logs")
	fmt.Println("  go run main.go -sort \"up,down,total\" /path/to/logs  # 生成3个排序维度的结果")
	fmt.Println("  go run main.go -sort \"up,total\" -output result.csv /path/to/logs  # 生成result_up.csv和result_total.csv")
	fmt.Println("")
	fmt.Println("CSV合并:")
	fmt.Println("  -merge     合并目录路径，将目录下所有up/down/total CSV文件按fields合并")
	fmt.Println("  -top       合并时每个分组提取的Top N条记录(默认10)")
	fmt.Println("  示例: ./access_log_analyzer -merge /path/to/csv_dir -fields \"dip,domain\" -top 10")
	fmt.Println("        会生成: merged_up.csv, merged_down.csv, top10_up.csv, top10_down.csv")
}

// exportToCSV 导出完整的统计结果到CSV文件
func exportToCSV(statsList []*TrafficStats, fieldIndexes map[string]int, csvTop int, outputFile string, sortType string) {
	// 生成文件名
	if outputFile == "" {
		timestamp := time.Now().Format("20060102_150405")
		outputFile = fmt.Sprintf("traffic_stats_%s.csv", timestamp)
	}

	// 在output文件名基础上添加排序类型后缀
	// 例如: result.csv -> result_up.csv, result_down.csv, result_total.csv
	baseName := strings.TrimSuffix(outputFile, filepath.Ext(outputFile))
	ext := filepath.Ext(outputFile)
	csvFileName := fmt.Sprintf("%s_%s%s", baseName, sortType, ext)

	file, err := os.Create(csvFileName)
	if err != nil {
		fmt.Printf("\n错误: 创建CSV文件失败: %v\n", err)
		return
	}
	defer file.Close()

	// 写入BOM标记,使Excel能正确识别UTF-8
	file.WriteString("\xEF\xBB\xBF")

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// 按字段索引排序，保证输出顺序一致
	type fieldPair struct {
		name string
		idx  int
	}
	sortedFields := make([]fieldPair, 0, len(fieldIndexes))
	for name, idx := range fieldIndexes {
		sortedFields = append(sortedFields, fieldPair{name, idx})
	}
	sort.Slice(sortedFields, func(i, j int) bool {
		return sortedFields[i].idx < sortedFields[j].idx
	})

	// 写入表头
	writer.WriteString("排名")
	for _, fp := range sortedFields {
		writer.WriteString("," + fp.name)
	}
	writer.WriteString(",上行流量(字节),上行流量,下行流量(字节),下行流量,总流量(字节),总流量,流数\n")

	// 确定导出行数
	exportCount := len(statsList)
	if csvTop > 0 && csvTop < exportCount {
		exportCount = csvTop
	}

	// 写入数据(限制行数)
	for i := 0; i < exportCount; i++ {
		stats := statsList[i]
		writer.WriteString(fmt.Sprintf("%d", i+1))
		for _, fp := range sortedFields {
			// 处理包含逗号的字段值,用引号包裹
			value := stats.Fields[fp.name]
			if strings.Contains(value, ",") || strings.Contains(value, "\"") {
				value = "\"" + strings.ReplaceAll(value, "\"", "\"\"") + "\""
			}
			writer.WriteString("," + value)
		}
		writer.WriteString(fmt.Sprintf(",%d,%s,%d,%s,%d,%s,%d\n",
			stats.UpTotal,
			formatBytes(stats.UpTotal),
			stats.DownTotal,
			formatBytes(stats.DownTotal),
			stats.UpTotal+stats.DownTotal,
			formatBytes(stats.UpTotal+stats.DownTotal),
			stats.FlowTotal,
		))
	}

	sortLabel := map[string]string{"up": "上行流量", "down": "下行流量", "total": "总流量"}
	label := sortLabel[sortType]
	if label == "" {
		label = sortType
	}
	fmt.Printf("\n✓ [%s] CSV文件已导出: %s (共 %d 条记录)", label, csvFileName, exportCount)
	if csvTop > 0 && len(statsList) > csvTop {
		fmt.Printf(", 总计 %d 条, 已限制为前 %d 条", len(statsList), csvTop)
	}
	fmt.Println()
}

// formatBytes 将字节数格式化为人类可读的形式
func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)

	if bytes >= TB {
		return fmt.Sprintf("%.2f TB", float64(bytes)/float64(TB))
	} else if bytes >= GB {
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	} else if bytes >= MB {
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	} else if bytes >= KB {
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	}
	return fmt.Sprintf("%d B", bytes)
}

// CSVRecord 存储CSV中的一条记录
type CSVRecord struct {
	Key       string            // 由fields指定的字段组合作为key
	Fields    map[string]string // 各字段的值
	UpTotal   int64
	DownTotal int64
	FlowTotal int64
	FlowCount int64
}

// mergeCSVFiles 合并目录下所有up/down/total CSV文件
func mergeCSVFiles(dirPath string, fieldsStr string, topN int) error {
	// 检查目录是否存在
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return fmt.Errorf("目录不存在: %s", dirPath)
	}

	// 解析字段
	fieldList := strings.Split(fieldsStr, ",")
	for i, f := range fieldList {
		fieldList[i] = strings.TrimSpace(f)
	}

	fmt.Printf("开始合并目录: %s\n", dirPath)
	fmt.Printf("合并字段: %s\n", fieldsStr)

	// 查找所有CSV文件
	var csvFiles []string
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".csv") {
			csvFiles = append(csvFiles, path)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("遍历目录失败: %v", err)
	}

	fmt.Printf("找到 %d 个CSV文件\n", len(csvFiles))

	// 按类型分类文件
	upFiles := []string{}
	downFiles := []string{}
	totalFiles := []string{}

	for _, file := range csvFiles {
		name := strings.ToLower(filepath.Base(file))
		if strings.Contains(name, "_up.csv") || strings.HasSuffix(name, "up.csv") {
			upFiles = append(upFiles, file)
		} else if strings.Contains(name, "_down.csv") || strings.HasSuffix(name, "down.csv") {
			downFiles = append(downFiles, file)
		} else if strings.Contains(name, "_total.csv") || strings.HasSuffix(name, "total.csv") {
			totalFiles = append(totalFiles, file)
		}
	}

	fmt.Printf("up文件: %d 个, down文件: %d 个, total文件: %d 个\n", len(upFiles), len(downFiles), len(totalFiles))

	// 合并up文件
	if len(upFiles) > 0 {
		fmt.Println("\n========== 合并 up 数据 ==========")
		err = mergeCSVFilesByType(upFiles, fieldList, "up", topN)
		if err != nil {
			return fmt.Errorf("合并up文件失败: %v", err)
		}
	}

	// 合并down文件
	if len(downFiles) > 0 {
		fmt.Println("\n========== 合并 down 数据 ==========")
		err = mergeCSVFilesByType(downFiles, fieldList, "down", topN)
		if err != nil {
			return fmt.Errorf("合并down文件失败: %v", err)
		}
	}

	// 合并total文件
	if len(totalFiles) > 0 {
		fmt.Println("\n========== 合并 total 数据 ==========")
		err = mergeCSVFilesByType(totalFiles, fieldList, "total", topN)
		if err != nil {
			return fmt.Errorf("合并total文件失败: %v", err)
		}
	}

	return nil
}

// mergeCSVFilesByType 合并同类型的CSV文件
func mergeCSVFilesByType(files []string, fieldList []string, sortType string, topN int) error {
	// 用于聚合的map
	aggregated := make(map[string]*CSVRecord)
	filesProcessed := 0

	// 读取所有文件
	for _, file := range files {
		fmt.Printf("  读取: %s\n", filepath.Base(file))

		f, err := os.Open(file)
		if err != nil {
			fmt.Printf("    警告: 打开文件失败: %v\n", err)
			continue
		}

		reader := csv.NewReader(f)
		// 跳过BOM
		reader.LazyQuotes = true

		// 读取表头
		headers, err := reader.Read()
		if err != nil {
			f.Close()
			fmt.Printf("    警告: 读取表头失败: %v\n", err)
			continue
		}

		// 找到字段索引
		fieldIndex := make(map[string]int)
		for i, h := range headers {
			h = strings.TrimSpace(h)
			// 去除BOM
			if i == 0 {
				h = strings.TrimPrefix(h, "\xEF\xBB\xBF")
			}
			fieldIndex[h] = i
		}

		// 检查必要字段是否存在
		hasRequiredFields := true
		for _, field := range fieldList {
			if _, ok := fieldIndex[field]; !ok {
				hasRequiredFields = false
				break
			}
		}

		if !hasRequiredFields {
			f.Close()
			fmt.Printf("    警告: 文件缺少必要字段，跳过\n")
			continue
		}

		// 读取数据行
		lineCount := 0
		for {
			record, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				continue
			}

			lineCount++

			// 跳过总计行
			if len(record) > 0 && (record[0] == "总计" || record[0] == "排名") {
				continue
			}

			// 构建key
			keyParts := []string{}
			fields := make(map[string]string)
			for _, field := range fieldList {
				if idx, ok := fieldIndex[field]; ok && idx < len(record) {
					value := strings.TrimSpace(record[idx])
					keyParts = append(keyParts, value)
					fields[field] = value
				}
			}

			key := strings.Join(keyParts, "|")

			// 解析流量数据
			upBytes := parseInt64(record, fieldIndex, "上行流量(字节)")
			downBytes := parseInt64(record, fieldIndex, "下行流量(字节)")
			totalBytes := parseInt64(record, fieldIndex, "总流量(字节)")
			flowCount := parseInt64(record, fieldIndex, "流数")

			// 聚合
			if agg, exists := aggregated[key]; exists {
				agg.UpTotal += upBytes
				agg.DownTotal += downBytes
				agg.FlowTotal += totalBytes
				agg.FlowCount += flowCount
			} else {
				aggregated[key] = &CSVRecord{
					Key:       key,
					Fields:    fields,
					UpTotal:   upBytes,
					DownTotal: downBytes,
					FlowTotal: totalBytes,
					FlowCount: flowCount,
				}
			}
		}

		f.Close()
		filesProcessed++
		fmt.Printf("    处理 %d 行数据\n", lineCount)
	}

	fmt.Printf("  共处理 %d 个文件, %d 个唯一组合\n", filesProcessed, len(aggregated))

	// 打印一些调试信息
	if len(aggregated) > 0 {
		fmt.Printf("  [调试] 前3条记录示例:\n")
		tempRecords := make([]*CSVRecord, 0, len(aggregated))
		for _, r := range aggregated {
			tempRecords = append(tempRecords, r)
		}
		// 按当前sortType排序
		sort.Slice(tempRecords, func(i, j int) bool {
			switch sortType {
			case "down":
				return tempRecords[i].DownTotal > tempRecords[j].DownTotal
			case "total":
				return tempRecords[i].FlowTotal > tempRecords[j].FlowTotal
			default:
				return tempRecords[i].UpTotal > tempRecords[j].UpTotal
			}
		})
		for i := 0; i < 3 && i < len(tempRecords); i++ {
			r := tempRecords[i]
			fmt.Printf("    [%s] key=%s, up=%d, down=%d, total=%d\n",
				sortType, r.Key, r.UpTotal, r.DownTotal, r.FlowTotal)
		}
	}

	// 转换为切片并排序
	records := make([]*CSVRecord, 0, len(aggregated))
	for _, record := range aggregated {
		records = append(records, record)
	}

	// 按类型排序
	sort.Slice(records, func(i, j int) bool {
		switch sortType {
		case "down":
			return records[i].DownTotal > records[j].DownTotal
		case "total":
			return records[i].FlowTotal > records[j].FlowTotal
		default: // up
			return records[i].UpTotal > records[j].UpTotal
		}
	})

	// 导出合并结果
	outputFile := fmt.Sprintf("merged_%s.csv", sortType)
	err := exportMergedCSV(records, fieldList, outputFile, sortType)
	if err != nil {
		return fmt.Errorf("导出CSV失败: %v", err)
	}

	// 提取每个key的topN
	if len(fieldList) >= 2 {
		fmt.Printf("  提取每个 %s 的 Top%d...\n", fieldList[0], topN)
		err = extractTopNPerKey(records, fieldList, sortType, topN)
		if err != nil {
			return fmt.Errorf("提取Top%d失败: %v", topN, err)
		}
	}

	return nil
}

// parseInt64 从记录中解析int64值
func parseInt64(record []string, fieldIndex map[string]int, fieldName string) int64 {
	if idx, ok := fieldIndex[fieldName]; ok && idx < len(record) {
		val := strings.TrimSpace(record[idx])
		// 移除逗号
		val = strings.ReplaceAll(val, ",", "")
		if v, err := strconv.ParseInt(val, 10, 64); err == nil {
			return v
		}
	}
	return 0
}

// exportMergedCSV 导出合并后的CSV
func exportMergedCSV(records []*CSVRecord, fieldList []string, outputFile string, sortType string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	// 写入BOM
	file.WriteString("\xEF\xBB\xBF")

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	header := []string{"排名"}
	header = append(header, fieldList...)
	header = append(header, "上行流量(字节)", "上行流量", "下行流量(字节)", "下行流量", "总流量(字节)", "总流量", "流数")
	writer.Write(header)

	// 写入数据
	totalUp := int64(0)
	totalDown := int64(0)
	totalFlow := int64(0)
	totalFlowCount := int64(0)

	for i, record := range records {
		row := []string{fmt.Sprintf("%d", i+1)}
		for _, field := range fieldList {
			row = append(row, record.Fields[field])
		}
		row = append(row,
			fmt.Sprintf("%d", record.UpTotal),
			formatBytes(record.UpTotal),
			fmt.Sprintf("%d", record.DownTotal),
			formatBytes(record.DownTotal),
			fmt.Sprintf("%d", record.FlowTotal),
			formatBytes(record.FlowTotal),
			fmt.Sprintf("%d", record.FlowCount),
		)
		writer.Write(row)

		totalUp += record.UpTotal
		totalDown += record.DownTotal
		totalFlow += record.FlowTotal
		totalFlowCount += record.FlowCount
	}

	// 写入总计行
	totalRow := []string{"总计"}
	for i := 0; i < len(fieldList); i++ {
		totalRow = append(totalRow, "")
	}
	totalRow = append(totalRow,
		fmt.Sprintf("%d", totalUp),
		formatBytes(totalUp),
		fmt.Sprintf("%d", totalDown),
		formatBytes(totalDown),
		fmt.Sprintf("%d", totalFlow),
		formatBytes(totalFlow),
		fmt.Sprintf("%d", totalFlowCount),
	)
	writer.Write(totalRow)

	sortLabel := map[string]string{"up": "上行流量", "down": "下行流量", "total": "总流量"}
	label := sortLabel[sortType]
	if label == "" {
		label = sortType
	}

	fmt.Printf("  ✓ [%s] 合并结果已导出: %s (共 %d 条记录)\n", label, outputFile, len(records))

	return nil
}

// extractTopNPerKey 提取每个key的topN记录
// key由fieldList的第一个字段确定（如dip），取每个key按sortType排序的前N条
func extractTopNPerKey(records []*CSVRecord, fieldList []string, sortType string, topN int) error {
	if len(fieldList) < 2 {
		return fmt.Errorf("至少需要2个字段才能提取TopN")
	}

	// 第一个字段作为分组key（如dip）
	groupField := fieldList[0]

	// 按第一个字段分组
	groups := make(map[string][]*CSVRecord)
	for _, record := range records {
		key := record.Fields[groupField]
		groups[key] = append(groups[key], record)
	}

	// 对每个组内按sortType排序，取topN
	var topNRecords []*CSVRecord
	for groupKey, groupRecords := range groups {
		// 复制记录，避免影响原始数据
		copiedRecords := make([]*CSVRecord, len(groupRecords))
		for i, r := range groupRecords {
			// 创建新的CSVRecord副本
			copiedRecords[i] = &CSVRecord{
				Key:       r.Key,
				Fields:    r.Fields,
				UpTotal:   r.UpTotal,
				DownTotal: r.DownTotal,
				FlowTotal: r.FlowTotal,
				FlowCount: r.FlowCount,
			}
		}

		// 对复制的记录排序
		sort.Slice(copiedRecords, func(i, j int) bool {
			switch sortType {
			case "down":
				return copiedRecords[i].DownTotal > copiedRecords[j].DownTotal
			case "total":
				return copiedRecords[i].FlowTotal > copiedRecords[j].FlowTotal
			default: // up
				return copiedRecords[i].UpTotal > copiedRecords[j].UpTotal
			}
		})

		// 取topN
		limit := topN
		if len(copiedRecords) < limit {
			limit = len(copiedRecords)
		}
		topNRecords = append(topNRecords, copiedRecords[:limit]...)

		_ = groupKey // 避免未使用警告
	}

	// 对topN结果排序：先按第一个字段（如dip）排序，同组内按流量排序
	sort.Slice(topNRecords, func(i, j int) bool {
		// 先按第一个字段排序
		keyI := topNRecords[i].Fields[groupField]
		keyJ := topNRecords[j].Fields[groupField]

		if keyI != keyJ {
			return keyI < keyJ // 按dip升序
		}

		// 同一dip内按流量排序
		switch sortType {
		case "down":
			return topNRecords[i].DownTotal > topNRecords[j].DownTotal
		case "total":
			return topNRecords[i].FlowTotal > topNRecords[j].FlowTotal
		default: // up
			return topNRecords[i].UpTotal > topNRecords[j].UpTotal
		}
	})

	// 导出topN
	outputFile := fmt.Sprintf("top%d_%s.csv", topN, sortType)
	err := exportMergedCSV(topNRecords, fieldList, outputFile, sortType)
	if err != nil {
		return fmt.Errorf("导出TopN CSV失败: %v", err)
	}

	sortLabel := map[string]string{"up": "上行流量", "down": "下行流量", "total": "总流量"}
	label := sortLabel[sortType]
	if label == "" {
		label = sortType
	}
	fmt.Printf("  ✓ [%s] Top%d已导出: %s (共 %d 条记录, %d 个分组)\n", label, topN, outputFile, len(topNRecords), len(groups))

	return nil
}
