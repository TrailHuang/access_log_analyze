package main

import (
	"access_log_analyze/internal/analyzer"
	"access_log_analyze/internal/config"
	"access_log_analyze/internal/merger"
	"access_log_analyze/pkg/models"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"

	"github.com/olekukonko/tablewriter"
)

func main() {
	// 定义命令行参数
	fields := flag.String("fields", "dip,domain", "统计字段,用逗号分隔")
	topN := flag.Int("top", 10, "显示Top N条记录")
	sortBy := flag.String("sort", "up", "排序方式: up(上行流量), down(下行流量), total(总流量)")
	csvTop := flag.Int("csv_top", 1000, "CSV文件导出最大行数(默认1000, 0表示全部)")
	workers := flag.Int("workers", 4, "并发协程数(默认4)")
	batchSize := flag.Int("batch_size", 0, "每批处理的文件数量后生成临时CSV(默认0表示不生成)")
	output := flag.String("output", "", "输出CSV文件名(默认自动生成)")
	logPath := flag.String("log_path", "", "日志文件路径(目录或tar.gz文件)")
	mergeDir := flag.String("merge", "", "合并目录: 将目录下所有up/down/total CSV文件按fields合并")

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
		if err := merger.MergeCSVFiles(*mergeDir, *fields, *topN); err != nil {
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
			merger.PrintHelp()
			os.Exit(1)
		}
		dirPath = flag.Arg(0)
	}

	// 解析命令行过滤器
	cmdSIPFilters := analyzer.ParseFilterPatterns(*sipFilter)
	cmdDIPFilters := analyzer.ParseFilterPatterns(*dipFilter)
	cmdDomainFilters := analyzer.ParseFilterPatterns(*domainFilter)

	// 加载配置文件
	filterConfig, err := config.LoadFilterConfig(*configFile)
	if err != nil {
		fmt.Printf("错误: %v\n", err)
		os.Exit(1)
	}

	// 合并配置（命令行优先级高于配置文件）
	mergedConfig, err := config.MergeConfig(filterConfig, *fields, *topN, *sortBy, *csvTop, *workers, *batchSize, *output, dirPath, *startTime, *endTime, cmdSIPFilters, cmdDIPFilters, cmdDomainFilters)
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
	filters := &models.LogFilters{
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
	fieldIndexes, err := analyzer.ParseFieldNames(*fields)
	if err != nil {
		fmt.Printf("错误: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("开始分析: %s\n", dirPath)
	fmt.Printf("统计字段: %s\n", *fields)
	fmt.Printf("显示Top: %d\n", *topN)
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
	startTimeInt, err := analyzer.ParseTime(mergedConfig.StartTime)
	if err != nil {
		fmt.Printf("错误: 解析开始时间失败: %v\n", err)
		startTimeInt = 0
	}
	endTimeInt, err := analyzer.ParseTime(mergedConfig.EndTime)
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

		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(strings.ToLower(info.Name()), ".tar.gz") {
			return nil
		}

		// 时间过滤
		if !analyzer.IsFileInTimeRange(info.Name(), startTimeInt, endTimeInt) {
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
	statsMap := analyzer.ProcessFilesConcurrent(tarGzFiles, fieldIndexes, filters, *workers, *batchSize, *output)

	// 输出统计结果
	analyzer.PrintResults(statsMap, fieldIndexes, *topN, *sortBy, *csvTop, *output)
}

// 注意: tablewriter的导入是为了保持兼容性，实际未使用
var _ = tablewriter.NewWriter
