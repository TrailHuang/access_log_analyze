package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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

// TrafficStats 存储流量统计数据
type TrafficStats struct {
	Key       string            // 统计key (由指定字段组合)
	Fields    map[string]string // 各字段的值
	UpTotal   int64
	DownTotal int64
}

func main() {
	// 定义命令行参数
	fields := flag.String("fields", "dip,domain", "统计字段,用逗号分隔。支持的字段: house_id, sip, dip, proto, sport, dport, domain, url, duration, utc_time, title, app_proto, biz_proto, referer, location, content, data_size, up_traffic, down_traffic, app_name")
	topN := flag.Int("top", 10, "显示Top N条记录")
	sortBy := flag.String("sort", "up", "排序方式: up(上行流量), down(下行流量), total(总流量)")
	csvTop := flag.Int("csv_top", 1000, "CSV文件导出最大行数(默认1000, 0表示全部)")
	workers := flag.Int("workers", 4, "并发协程数(默认4)")
	output := flag.String("output", "", "输出CSV文件名(默认自动生成)")
	logPath := flag.String("log_path", "", "日志文件路径(目录或tar.gz文件)")

	// 过滤参数
	sipFilter := flag.String("sip", "", "源IP过滤,支持逗号分隔多个值,支持*模糊匹配")
	dipFilter := flag.String("dip", "", "目的IP过滤,支持逗号分隔多个值,支持*模糊匹配")
	domainFilter := flag.String("domain", "", "域名过滤,支持逗号分隔多个值,支持*模糊匹配")

	flag.Parse()

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

	// 解析过滤器
	filters := &LogFilters{
		SIPFilters:    parseFilterPatterns(*sipFilter),
		DIPFilters:    parseFilterPatterns(*dipFilter),
		DomainFilters: parseFilterPatterns(*domainFilter),
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

	sortLabel := map[string]string{"up": "上行流量", "down": "下行流量", "total": "总流量"}
	fmt.Printf("排序方式: %s\n", sortLabel[*sortBy])
	fmt.Printf("并发协程: %d\n", *workers)
	if filters.HasFilters() {
		fmt.Printf("过滤条件:\n")
		if len(filters.SIPFilters) > 0 {
			fmt.Printf("  源IP: %v\n", *sipFilter)
		}
		if len(filters.DIPFilters) > 0 {
			fmt.Printf("  目的IP: %v\n", *dipFilter)
		}
		if len(filters.DomainFilters) > 0 {
			fmt.Printf("  域名: %v\n", *domainFilter)
		}
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

		tarGzFiles = append(tarGzFiles, path)
		return nil
	})

	if err != nil {
		fmt.Printf("错误: 遍历目录时出错: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("找到 %d 个tar.gz文件\n", len(tarGzFiles))

	// 并发处理文件
	statsMap := processFilesConcurrent(tarGzFiles, fieldIndexes, filters, *workers)

	// 输出统计结果
	printResults(statsMap, fieldIndexes, *topN, *sortBy, *csvTop, *output)
}

// processFilesConcurrent 并发处理多个tar.gz文件
func processFilesConcurrent(files []string, fieldIndexes map[string]int, filters *LogFilters, numWorkers int) map[string]*TrafficStats {
	// 限制最大协程数不超过文件数
	if numWorkers > len(files) {
		numWorkers = len(files)
	}

	if numWorkers == 0 {
		return make(map[string]*TrafficStats)
	}

	fmt.Printf("使用 %d 个协程并发处理\n", numWorkers)

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

			for filePath := range taskCh {
				// 每个协程独立统计
				localStats := make(map[string]*TrafficStats)

				err := processTarGz(filePath, localStats, fieldIndexes, filters)
				if err != nil {
					fileName := filepath.Base(filePath)
					fmt.Printf("  [Worker %d] 警告: 处理文件 %s 时出错: %v\n", workerID, fileName, err)
				}

				// 发送结果
				resultCh <- result{stats: localStats, err: err}
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
		} else {
			// key不存在,直接复制
			dst[key] = &TrafficStats{
				Key:       srcStats.Key,
				Fields:    srcStats.Fields,
				UpTotal:   srcStats.UpTotal,
				DownTotal: srcStats.DownTotal,
			}
		}
	}
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

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// 跳过空行
		if strings.TrimSpace(line) == "" {
			continue
		}

		// 解析CSV格式的数据(使用|作为分隔符)
		csvReader := csv.NewReader(strings.NewReader(line))
		csvReader.Comma = '|'
		csvReader.FieldsPerRecord = -1 // 允许字段数不固定

		fields, err := csvReader.Read()
		if err != nil {
			fmt.Printf("  警告: 解析第 %d 行失败: %v\n", lineNum, err)
			continue
		}

		// 日志格式: HouseId|源IP|目的IP|协议类型|源端口|目的端口|域名|URL|Duration|UTC时间|Title|应用层协议|业务层协议|Referer|Location|网站内容|访问数据量|上行流量|下行流量|应用名称
		// 字段索引: 0       1     2      3       4      5      6    7   8        9        10    11         12         13      14       15       16        17      18      19
		// 实际数据: 16|175.8.116.202|123.180.157.193|1|16979|443|||48|1776150396||1|8|28||||0|0|123665|

		if len(fields) < 20 {
			fmt.Printf("  警告: 第 %d 行字段数不足 (%d < 20)\n", lineNum, len(fields))
			continue
		}

		// 构建统计key和字段值映射
		keyParts := make([]string, 0, len(fieldIndexes))
		fieldValues := make(map[string]string)

		// 按固定顺序提取统计字段(避免map遍历顺序随机导致key不一致)
		// 先按fieldIdx排序,确保顺序固定
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

		key := strings.Join(keyParts, "|")

		// 应用过滤条件
		sip := fieldValues["sip"]
		dip := fieldValues["dip"]
		domain := fieldValues["domain"]

		if !MatchFilter(sip, filters.SIPFilters) {
			continue
		}
		if !MatchFilter(dip, filters.DIPFilters) {
			continue
		}
		if !MatchFilter(domain, filters.DomainFilters) {
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
		} else {
			statsMap[key] = &TrafficStats{
				Key:       key,
				Fields:    fieldValues,
				UpTotal:   upTraffic,
				DownTotal: downTraffic,
			}
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

	// 按指定方式排序
	sort.Slice(statsList, func(i, j int) bool {
		switch sortBy {
		case "down":
			return statsList[i].DownTotal > statsList[j].DownTotal
		case "total":
			return (statsList[i].UpTotal + statsList[i].DownTotal) > (statsList[j].UpTotal + statsList[j].DownTotal)
		default: // up
			return statsList[i].UpTotal > statsList[j].UpTotal
		}
	})

	// 确定显示数量
	displayCount := topN
	if len(statsList) < displayCount {
		displayCount = len(statsList)
	}

	// 创建表格
	headers := []string{"排名"}
	for fieldName := range fieldIndexes {
		headers = append(headers, fieldName)
	}
	headers = append(headers, "上行流量\n(字节)", "上行流量\n", "下行流量\n(字节)", "下行流量\n", "总流量\n(字节)", "总流量\n")

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

	for i := 0; i < displayCount; i++ {
		stats := statsList[i]

		row := []string{fmt.Sprintf("%d", i+1)}
		for fieldName := range fieldIndexes {
			row = append(row, stats.Fields[fieldName])
		}

		totalBytes := stats.UpTotal + stats.DownTotal
		row = append(row,
			fmt.Sprintf("%d", stats.UpTotal),
			formatBytes(stats.UpTotal),
			fmt.Sprintf("%d", stats.DownTotal),
			formatBytes(stats.DownTotal),
			fmt.Sprintf("%d", totalBytes),
			formatBytes(totalBytes),
		)

		table.Append(row)
		totalUp += stats.UpTotal
		totalDown += stats.DownTotal
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
	)
	table.Append(totalRow)

	// 渲染表格
	fmt.Println()
	table.Render()
	fmt.Printf("\n共 %d 个唯一组合, 显示 Top %d\n", len(statsMap), displayCount)

	// 导出CSV
	exportToCSV(statsList, fieldIndexes, csvTop, outputFile)
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
	fmt.Println("")
	fmt.Println("排序参数:")
	fmt.Println("  -sort      排序方式: up(上行流量), down(下行流量), total(总流量) (默认: up)")
	fmt.Println("")
	fmt.Println("示例:")
	fmt.Println("  go run main.go /path/to/logs")
	fmt.Println("  go run main.go -log_path /path/to/logs -top 20")
	fmt.Println("  go run main.go -fields \"sip,dip,domain\" -top 5 /path/to/logs")
	fmt.Println("  go run main.go -sip 192.168.1.100 -dip 10.0.0.* /path/to/logs")
	fmt.Println("  go run main.go -domain \"*.example.com,test.com\" /path/to/logs")
	fmt.Println("  go run main.go -sort down -top 20 /path/to/logs")
	fmt.Println("  go run main.go -sort total /path/to/logs")
}

// exportToCSV 导出完整的统计结果到CSV文件
func exportToCSV(statsList []*TrafficStats, fieldIndexes map[string]int, csvTop int, outputFile string) {
	// 生成文件名
	if outputFile == "" {
		timestamp := time.Now().Format("20060102_150405")
		outputFile = fmt.Sprintf("traffic_stats_%s.csv", timestamp)
	}

	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("\n错误: 创建CSV文件失败: %v\n", err)
		return
	}
	defer file.Close()

	// 写入BOM标记,使Excel能正确识别UTF-8
	file.WriteString("\xEF\xBB\xBF")

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	writer.WriteString("排名")
	for fieldName := range fieldIndexes {
		writer.WriteString("," + fieldName)
	}
	writer.WriteString(",上行流量(字节),下行流量(字节),总流量(字节),上行流量,下行流量,总流量\n")

	// 确定导出行数
	exportCount := len(statsList)
	if csvTop > 0 && csvTop < exportCount {
		exportCount = csvTop
	}

	// 写入数据(限制行数)
	for i := 0; i < exportCount; i++ {
		stats := statsList[i]
		writer.WriteString(fmt.Sprintf("%d", i+1))
		for fieldName := range fieldIndexes {
			// 处理包含逗号的字段值,用引号包裹
			value := stats.Fields[fieldName]
			if strings.Contains(value, ",") || strings.Contains(value, "\"") {
				value = "\"" + strings.ReplaceAll(value, "\"", "\"\"") + "\""
			}
			writer.WriteString("," + value)
		}
		writer.WriteString(fmt.Sprintf(",%d,%d,%d,%s,%s,%s\n",
			stats.UpTotal,
			stats.DownTotal,
			stats.UpTotal+stats.DownTotal,
			formatBytes(stats.UpTotal),
			formatBytes(stats.DownTotal),
			formatBytes(stats.UpTotal+stats.DownTotal),
		))
	}

	fmt.Printf("\n✓ CSV文件已导出: %s (共 %d 条记录)", outputFile, exportCount)
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
