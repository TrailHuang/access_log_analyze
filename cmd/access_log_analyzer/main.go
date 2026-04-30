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
	// 定义命令行参数（不带默认值）
	fields := flag.String("fields", "", "统计字段,用逗号分隔")
	topN := flag.Int("top", 0, "显示Top N条记录")
	sortBy := flag.String("sort", "", "排序方式: up(上行流量), down(下行流量), total(总流量)")
	csvTop := flag.Int("csv_top", 0, "CSV文件导出最大行数(0表示全部)")
	workers := flag.Int("workers", 0, "并发协程数")
	batchSize := flag.Int("batch_size", 0, "每批处理的文件数量后生成临时CSV(0表示不生成)")
	output := flag.String("output", "", "输出CSV文件名(默认自动生成)")
	logPath := flag.String("log_path", "", "日志文件路径(目录或tar.gz文件)")
	mergeDir := flag.String("merge", "", "合并目录: 将目录下所有up/down/total CSV文件按fields合并")
	duration := flag.Float64("duration", 0, "持续时间(秒)，用于计算Mbps")

	// 过滤参数
	sipFilter := flag.String("sip", "", "源IP过滤,支持逗号分隔多个值,支持*模糊匹配")
	dipFilter := flag.String("dip", "", "目的IP过滤,支持逗号分隔多个值,支持*模糊匹配")
	domainFilter := flag.String("domain", "", "域名过滤,支持逗号分隔多个值,支持*模糊匹配")
	sportFilter := flag.String("sport", "", "源端口过滤,支持逗号分隔多个值,支持*模糊匹配")
	dportFilter := flag.String("dport", "", "目的端口过滤,支持逗号分隔多个值,支持*模糊匹配")
	sipReverse := flag.Bool("sip_reverse", false, "源IP反向过滤：排除匹配的项")
	dipReverse := flag.Bool("dip_reverse", false, "目的IP反向过滤：排除匹配的项")
	domainReverse := flag.Bool("domain_reverse", false, "域名反向过滤：排除匹配的项")
	sportReverse := flag.Bool("sport_reverse", false, "源端口反向过滤：排除匹配的项")
	dportReverse := flag.Bool("dport_reverse", false, "目的端口反向过滤：排除匹配的项")
	sipFilterMode := flag.Int("sip_filter_mode", 0, "源IP空值过滤模式：0=统计所有(默认), 1=只统计空值, 2=只统计非空值")
	dipFilterMode := flag.Int("dip_filter_mode", 0, "目的IP空值过滤模式：0=统计所有(默认), 1=只统计空值, 2=只统计非空值")
	domainFilterMode := flag.Int("domain_filter_mode", 0, "域名空值过滤模式：0=统计所有(默认), 1=只统计空值, 2=只统计非空值")
	sportFilterMode := flag.Int("sport_filter_mode", 0, "源端口空值过滤模式：0=统计所有(默认), 1=只统计空值, 2=只统计非空值")
	dportFilterMode := flag.Int("dport_filter_mode", 0, "目的端口空值过滤模式：0=统计所有(默认), 1=只统计空值, 2=只统计非空值")
	startTime := flag.String("start", "", "开始时间(格式: YYYYMMDDHHmmss，精确到秒)")
	endTime := flag.String("end", "", "结束时间(格式: YYYYMMDDHHmmss，精确到秒)")
	configFile := flag.String("config", "", "过滤器配置文件路径(JSON格式，不指定则使用config.json)")
	pprofSwitch := flag.Bool("pprof", false, "是否开启性能分析")

	flag.Parse()

	// 如果是merge模式，直接处理并退出
	if *mergeDir != "" {
		if err := merger.MergeCSVFiles(*mergeDir, *fields, *topN, *duration, *output); err != nil {
			fmt.Printf("错误: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 验证排序参数（如果指定了排序参数）
	if *sortBy != "" && *sortBy != "up" && *sortBy != "down" && *sortBy != "total" {
		fmt.Printf("错误: 无效的排序方式: %s (支持: up, down, total)\n", *sortBy)
		os.Exit(1)
	}

	// 验证协程数（如果指定了协程数）
	if *workers < 0 {
		fmt.Printf("错误: 协程数不能为负数\n")
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
	cmdSportFilters := analyzer.ParseFilterPatterns(*sportFilter)
	cmdDportFilters := analyzer.ParseFilterPatterns(*dportFilter)

	// 加载配置文件
	filterConfig, err := config.LoadFilterConfig(*configFile)
	if err != nil {
		fmt.Printf("错误: 加载配置文件失败: %v\n", err)
		os.Exit(1)
	}

	// 合并配置（命令行优先级高于配置文件）
	mergedConfig, err := config.MergeConfig(filterConfig, *fields, *topN, *sortBy, *csvTop, *workers, *batchSize, *output, dirPath, *startTime, *endTime, cmdSIPFilters, cmdDIPFilters, cmdDomainFilters, cmdSportFilters, cmdDportFilters, *sipReverse, *dipReverse, *domainReverse, *sportReverse, *dportReverse, *sipFilterMode, *dipFilterMode, *domainFilterMode, *sportFilterMode, *dportFilterMode, *pprofSwitch)
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

	// 性能分析: CPU profile (根据配置开关控制)
	if mergedConfig.PprofSwitch {
		cpuProfile, err := os.Create("cpu_profile.prof")
		if err != nil {
			fmt.Printf("创建CPU profile文件失败: %v\n", err)
			return
		}
		pprof.StartCPUProfile(cpuProfile)
		defer pprof.StopCPUProfile()
		fmt.Println("性能分析已开启")
	}

	// 性能分析: 内存 profile (根据配置开关控制)
	if mergedConfig.PprofSwitch {
		defer func() {
			memProfile, err := os.Create("mem_profile.prof")
			if err != nil {
				fmt.Printf("创建内存profile文件失败: %v\n", err)
				return
			}
			pprof.WriteHeapProfile(memProfile)
			memProfile.Close()
			fmt.Println("内存profile已保存: mem_profile.prof")
		}()
	}

	// 创建过滤器
	filters := &models.LogFilters{
		SIPFilters:       mergedConfig.SIPFilters,
		DIPFilters:       mergedConfig.DIPFilters,
		DomainFilters:    mergedConfig.DomainFilters,
		SportFilters:     mergedConfig.SportFilters,
		DportFilters:     mergedConfig.DportFilters,
		SIPReverse:       mergedConfig.SIPReverse,
		DIPReverse:       mergedConfig.DIPReverse,
		DomainReverse:    mergedConfig.DomainReverse,
		SportReverse:     mergedConfig.SportReverse,
		DportReverse:     mergedConfig.DportReverse,
		SIPFilterMode:    mergedConfig.SIPFilterMode,
		DIPFilterMode:    mergedConfig.DIPFilterMode,
		DomainFilterMode: mergedConfig.DomainFilterMode,
		SportFilterMode:  mergedConfig.SportFilterMode,
		DportFilterMode:  mergedConfig.DportFilterMode,
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
			reverseMark := ""
			if filters.SIPReverse {
				reverseMark = " [反向]"
			}
			fmt.Printf("  源IP: %v%s\n", filters.SIPFilters, reverseMark)
		}
		if len(filters.DIPFilters) > 0 {
			reverseMark := ""
			if filters.DIPReverse {
				reverseMark = " [反向]"
			}
			fmt.Printf("  目的IP: %v%s\n", filters.DIPFilters, reverseMark)
		}
		if len(filters.DomainFilters) > 0 {
			reverseMark := ""
			if filters.DomainReverse {
				reverseMark = " [反向]"
			}
			fmt.Printf("  域名: %v%s\n", filters.DomainFilters, reverseMark)
		}
		if len(filters.SportFilters) > 0 {
			reverseMark := ""
			if filters.SportReverse {
				reverseMark = " [反向]"
			}
			fmt.Printf("  源端口: %v%s\n", filters.SportFilters, reverseMark)
		}
		if len(filters.DportFilters) > 0 {
			reverseMark := ""
			if filters.DportReverse {
				reverseMark = " [反向]"
			}
			fmt.Printf("  目的端口: %v%s\n", filters.DportFilters, reverseMark)
		}
		if filters.SIPFilterMode != 0 {
			modeName := "未知"
			if filters.SIPFilterMode == 1 {
				modeName = "仅统计空值"
			} else if filters.SIPFilterMode == 2 {
				modeName = "仅统计非空值"
			}
			fmt.Printf("  源IP: [%s]\n", modeName)
		}
		if filters.DIPFilterMode != 0 {
			modeName := "未知"
			if filters.DIPFilterMode == 1 {
				modeName = "仅统计空值"
			} else if filters.DIPFilterMode == 2 {
				modeName = "仅统计非空值"
			}
			fmt.Printf("  目的IP: [%s]\n", modeName)
		}
		if filters.DomainFilterMode != 0 {
			modeName := "未知"
			if filters.DomainFilterMode == 1 {
				modeName = "仅统计空值"
			} else if filters.DomainFilterMode == 2 {
				modeName = "仅统计非空值"
			}
			fmt.Printf("  域名: [%s]\n", modeName)
		}
		if filters.SportFilterMode != 0 {
			modeName := "未知"
			if filters.SportFilterMode == 1 {
				modeName = "仅统计空值"
			} else if filters.SportFilterMode == 2 {
				modeName = "仅统计非空值"
			}
			fmt.Printf("  源端口: [%s]\n", modeName)
		}
		if filters.DportFilterMode != 0 {
			modeName := "未知"
			if filters.DportFilterMode == 1 {
				modeName = "仅统计空值"
			} else if filters.DportFilterMode == 2 {
				modeName = "仅统计非空值"
			}
			fmt.Printf("  目的端口: [%s]\n", modeName)
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
