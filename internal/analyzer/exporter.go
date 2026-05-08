package analyzer

import (
	"access_log_analyze/pkg/models"
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ExportConfig 导出配置
type ExportConfig struct {
	OutputFile  string
	ExportStart string // 导出时间范围开始 YYYYMMDDHHmmss
	ExportEnd   string // 导出时间范围结束 YYYYMMDDHHmmss
	Filters     *models.LogFilters
	Workers     int
}

// ExportTarGzFiles 并发导出话单
func ExportTarGzFiles(files []string, config *ExportConfig) (int64, error) {
	numWorkers := config.Workers
	if numWorkers <= 0 {
		numWorkers = 4
	}
	if numWorkers > len(files) {
		numWorkers = len(files)
	}
	if numWorkers == 0 {
		return 0, fmt.Errorf("没有文件需要处理")
	}

	taskCh := make(chan string, len(files))
	for _, f := range files {
		taskCh <- f
	}
	close(taskCh)

	type fileResult struct {
		count int64
		err   error
	}
	resultCh := make(chan fileResult, len(files))

	var fileSeqCounter int64

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			count, err := processFilesForExport(taskCh, workerID, config, &fileSeqCounter)
			if err != nil {
				fmt.Printf("  [Worker %d] 错误: %v\n", workerID, err)
			}
			resultCh <- fileResult{count: count, err: err}
		}(i)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var totalExported int64
	for res := range resultCh {
		totalExported += res.count
	}

	return totalExported, nil
}

// processFilesForExport 处理多个文件并直接写入CSV
func processFilesForExport(taskCh <-chan string, workerID int, config *ExportConfig, fileSeqCounter *int64) (int64, error) {
	var totalExported int64
	localRecords := make([][]string, 0, 100000)

	var file *os.File
	var writer *csv.Writer
	var outputPath string
	var seq int
	fileCreated := false

	ensureFile := func() error {
		if fileCreated {
			return nil
		}
		seq = int(atomicAddInt64(fileSeqCounter, 1) - 1)
		outputPath = generateOutputFileName(config.OutputFile, seq)
		var err error
		file, writer, err = createCSVFile(outputPath)
		if err != nil {
			return fmt.Errorf("创建输出文件失败: %w", err)
		}
		fileCreated = true
		return nil
	}

	writeRecord := func(rec []string) error {
		if err := ensureFile(); err != nil {
			return err
		}
		localRecords = append(localRecords, rec)
		if len(localRecords) >= 100000 {
			for _, r := range localRecords {
				writer.Write(r)
			}
			writer.Flush()
			totalExported += int64(len(localRecords))
			localRecords = localRecords[:0]

			file.Close()
			seq = int(atomicAddInt64(fileSeqCounter, 1) - 1)
			outputPath = generateOutputFileName(config.OutputFile, seq)
			var err error
			file, writer, err = createCSVFile(outputPath)
			if err != nil {
				return fmt.Errorf("创建输出文件失败: %w", err)
			}
		}
		return nil
	}

	for filePath := range taskCh {
		count, err := processTarGzForExportWithCallback(filePath, config, writeRecord)
		if err != nil {
			fmt.Printf("  [Worker %d] 警告: 处理文件 %s 时出错: %v\n", workerID, filepath.Base(filePath), err)
			continue
		}

		fmt.Printf("  [Worker %d] ✓ %s 处理完成，匹配 %d 条记录\n", workerID, filepath.Base(filePath), count)
	}

	if len(localRecords) > 0 {
		for _, rec := range localRecords {
			writer.Write(rec)
		}
		writer.Flush()
		totalExported += int64(len(localRecords))
	}

	if fileCreated {
		file.Close()
		// 如果只写了表头没有实际数据，删除空文件
		if totalExported == 0 {
			os.Remove(outputPath)
		}
	}

	return totalExported, nil
}

// atomicAddInt64 原子加法
func atomicAddInt64(val *int64, delta int64) int64 {
	var mu sync.Mutex
	mu.Lock()
	defer mu.Unlock()
	*val += delta
	return *val
}

// generateOutputFileName 生成输出文件名
func generateOutputFileName(baseName string, seq int) string {
	if baseName == "" {
		baseName = "export_records.csv"
	}

	ext := filepath.Ext(baseName)
	name := strings.TrimSuffix(baseName, ext)

	if seq == 0 {
		return fmt.Sprintf("%s%s", name, ext)
	}
	return fmt.Sprintf("%s_%d%s", name, seq, ext)
}

// createCSVFile 创建CSV文件并写入表头
func createCSVFile(path string) (*os.File, *csv.Writer, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}

	file.WriteString("\xEF\xBB\xBF")

	writer := csv.NewWriter(file)

	header := []string{
		"HouseId", "源IP", "目的IP", "协议类型", "源端口", "目的端口",
		"域名", "URL", "Duration", "UTC时间", "Title", "流量类型",
		"应用层协议", "业务层协议", "Referer", "Location", "网站内容",
		"访问数据量", "上行流量", "下行流量", "应用名称",
	}
	writer.Write(header)

	return file, writer, nil
}

// processTarGzForExportWithCallback 处理单个tar.gz文件，通过回调函数逐条返回记录
func processTarGzForExportWithCallback(filePath string, config *ExportConfig, callback func([]string) error) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return 0, fmt.Errorf("创建gzip reader失败: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	var count int

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, fmt.Errorf("读取tar文件失败: %w", err)
		}

		if header.Typeflag == tar.TypeReg && strings.HasSuffix(strings.ToLower(header.Name), ".txt") {
			n, err := processLogForExportWithCallback(tarReader, config, callback)
			if err != nil {
				return count, fmt.Errorf("处理日志文件 %s 失败: %w", header.Name, err)
			}
			count += n
		}
	}

	return count, nil
}

// processLogForExportWithCallback 解析日志文件并通过回调函数逐条返回匹配的记录
func processLogForExportWithCallback(reader io.Reader, config *ExportConfig, callback func([]string) error) (int, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	positions := make([]fieldPos, 0, 32)
	fields := make([]string, 21) // 预分配字段数组，循环内复用

	needFilter := config.Filters.HasFilters()
	needTimeFilter := config.ExportStart != "" || config.ExportEnd != ""

	type filterField struct {
		name string
		idx  int
	}
	filterFields := []filterField{
		{"sip", 1},
		{"dip", 2},
		{"domain", 6},
		{"sport", 4},
		{"dport", 5},
		{"url", 7},
	}

	var count int

	for scanner.Scan() {
		lineBytes := scanner.Bytes()

		if len(lineBytes) == 0 {
			continue
		}
		allSpace := true
		for _, b := range lineBytes {
			if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
				allSpace = false
				break
			}
		}
		if allSpace {
			continue
		}

		positions = findFieldPositions(lineBytes, positions[:0])

		if len(positions) < 21 {
			continue
		}

		// 一次性提取所有字段（使用 unsafe.String 零拷贝，仅当前迭代内有效）
		for i := 0; i < 21; i++ {
			fields[i] = getFieldStringUnsafe(lineBytes, positions, i)
		}

		if needFilter {
			if config.Filters.ExportFilterLogic == 1 {
				matched := false
				for _, ff := range filterFields {
					value := fields[ff.idx]

					switch ff.name {
					case "sip":
						if len(config.Filters.SIPFilters) > 0 && MatchFilter(value, config.Filters.SIPFilters, config.Filters.SIPReverse) {
							matched = true
						}
					case "dip":
						if len(config.Filters.DIPFilters) > 0 && MatchFilter(value, config.Filters.DIPFilters, config.Filters.DIPReverse) {
							matched = true
						}
					case "domain":
						if len(config.Filters.DomainFilters) > 0 && MatchFilter(value, config.Filters.DomainFilters, config.Filters.DomainReverse) {
							matched = true
						}
					case "sport":
						if len(config.Filters.SportFilters) > 0 && MatchFilter(value, config.Filters.SportFilters, config.Filters.SportReverse) {
							matched = true
						}
					case "dport":
						if len(config.Filters.DportFilters) > 0 && MatchFilter(value, config.Filters.DportFilters, config.Filters.DportReverse) {
							matched = true
						}
					case "url":
						if len(config.Filters.URLFilters) > 0 && MatchURLFilter(value, config.Filters) {
							matched = true
						}
					}

					if matched {
						break
					}
				}
				if !matched {
					continue
				}
			} else {
				skip := false
				for _, ff := range filterFields {
					value := fields[ff.idx]

					switch ff.name {
					case "sip":
						if !MatchFilter(value, config.Filters.SIPFilters, config.Filters.SIPReverse) {
							skip = true
						}
					case "dip":
						if !MatchFilter(value, config.Filters.DIPFilters, config.Filters.DIPReverse) {
							skip = true
						}
					case "domain":
						if !MatchFilter(value, config.Filters.DomainFilters, config.Filters.DomainReverse) {
							skip = true
						}
					case "sport":
						if !MatchFilter(value, config.Filters.SportFilters, config.Filters.SportReverse) {
							skip = true
						}
					case "dport":
						if !MatchFilter(value, config.Filters.DportFilters, config.Filters.DportReverse) {
							skip = true
						}
					case "url":
						if !MatchURLFilter(value, config.Filters) {
							skip = true
						}
					}

					if skip {
						break
					}
				}
				if skip {
					continue
				}
			}
		}

		if config.Filters.SIPFilterMode != 0 || config.Filters.DIPFilterMode != 0 || config.Filters.DomainFilterMode != 0 || config.Filters.SportFilterMode != 0 || config.Filters.DportFilterMode != 0 || config.Filters.URLFilterMode != 0 {
			skip := false

			if config.Filters.SIPFilterMode != 0 {
				isEmpty := fields[1] == "" || fields[1] == "-"
				if (config.Filters.SIPFilterMode == 1 && !isEmpty) || (config.Filters.SIPFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.DIPFilterMode != 0 {
				isEmpty := fields[2] == "" || fields[2] == "-"
				if (config.Filters.DIPFilterMode == 1 && !isEmpty) || (config.Filters.DIPFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.DomainFilterMode != 0 {
				isEmpty := fields[6] == "" || fields[6] == "-"
				if (config.Filters.DomainFilterMode == 1 && !isEmpty) || (config.Filters.DomainFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.SportFilterMode != 0 {
				isEmpty := fields[4] == "" || fields[4] == "-"
				if (config.Filters.SportFilterMode == 1 && !isEmpty) || (config.Filters.SportFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.DportFilterMode != 0 {
				isEmpty := fields[5] == "" || fields[5] == "-"
				if (config.Filters.DportFilterMode == 1 && !isEmpty) || (config.Filters.DportFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.URLFilterMode != 0 {
				isEmpty := fields[7] == "" || fields[7] == "-"
				if (config.Filters.URLFilterMode == 1 && !isEmpty) || (config.Filters.URLFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if skip {
				continue
			}
		}

		if needTimeFilter {
			if !matchTimeRange(fields[9], config.ExportStart, config.ExportEnd) {
				continue
			}
		}

		// 构建安全 record（克隆 unsafe string 为独立副本，使 callback 可安全持有）
		record := make([]string, 21)
		for i := 0; i < 21; i++ {
			record[i] = strings.Clone(fields[i])
		}

		if err := callback(record); err != nil {
			return count, err
		}
		count++
	}

	return count, scanner.Err()
}

// processTarGzForExport 处理单个tar.gz文件并返回匹配的记录
func processTarGzForExport(filePath string, config *ExportConfig) ([][]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("创建gzip reader失败: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	var records [][]string

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("读取tar文件失败: %w", err)
		}

		if header.Typeflag == tar.TypeReg && strings.HasSuffix(strings.ToLower(header.Name), ".txt") {
			matched, err := processLogForExport(tarReader, config)
			if err != nil {
				return nil, fmt.Errorf("处理日志文件 %s 失败: %w", header.Name, err)
			}
			records = append(records, matched...)
		}
	}

	return records, nil
}

// processLogForExport 解析日志文件并返回匹配的记录
func processLogForExport(reader io.Reader, config *ExportConfig) ([][]string, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	var records [][]string
	positions := make([]fieldPos, 0, 32)
	fields := make([]string, 21) // 预分配字段数组，循环内复用

	needFilter := config.Filters.HasFilters()
	needTimeFilter := config.ExportStart != "" || config.ExportEnd != ""

	type filterField struct {
		name string
		idx  int
	}
	filterFields := []filterField{
		{"sip", 1},
		{"dip", 2},
		{"domain", 6},
		{"sport", 4},
		{"dport", 5},
		{"url", 7},
	}

	for scanner.Scan() {
		lineBytes := scanner.Bytes()

		if len(lineBytes) == 0 {
			continue
		}
		allSpace := true
		for _, b := range lineBytes {
			if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
				allSpace = false
				break
			}
		}
		if allSpace {
			continue
		}

		positions = findFieldPositions(lineBytes, positions[:0])

		if len(positions) < 21 {
			continue
		}

		// 一次性提取所有字段（使用 unsafe.String 零拷贝，仅当前迭代内有效）
		for i := 0; i < 21; i++ {
			fields[i] = getFieldStringUnsafe(lineBytes, positions, i)
		}

		if needFilter {
			if config.Filters.ExportFilterLogic == 1 {
				// 或模式：满足任一过滤条件即可
				matched := false
				for _, ff := range filterFields {
					value := fields[ff.idx]

					switch ff.name {
					case "sip":
						if len(config.Filters.SIPFilters) > 0 && MatchFilter(value, config.Filters.SIPFilters, config.Filters.SIPReverse) {
							matched = true
						}
					case "dip":
						if len(config.Filters.DIPFilters) > 0 && MatchFilter(value, config.Filters.DIPFilters, config.Filters.DIPReverse) {
							matched = true
						}
					case "domain":
						if len(config.Filters.DomainFilters) > 0 && MatchFilter(value, config.Filters.DomainFilters, config.Filters.DomainReverse) {
							matched = true
						}
					case "sport":
						if len(config.Filters.SportFilters) > 0 && MatchFilter(value, config.Filters.SportFilters, config.Filters.SportReverse) {
							matched = true
						}
					case "dport":
						if len(config.Filters.DportFilters) > 0 && MatchFilter(value, config.Filters.DportFilters, config.Filters.DportReverse) {
							matched = true
						}
					case "url":
						if len(config.Filters.URLFilters) > 0 && MatchURLFilter(value, config.Filters) {
							matched = true
						}
					}

					if matched {
						break
					}
				}
				if !matched {
					continue
				}
			} else {
				// 与模式（默认）：所有过滤条件都需满足
				skip := false
				for _, ff := range filterFields {
					value := fields[ff.idx]

					switch ff.name {
					case "sip":
						if !MatchFilter(value, config.Filters.SIPFilters, config.Filters.SIPReverse) {
							skip = true
						}
					case "dip":
						if !MatchFilter(value, config.Filters.DIPFilters, config.Filters.DIPReverse) {
							skip = true
						}
					case "domain":
						if !MatchFilter(value, config.Filters.DomainFilters, config.Filters.DomainReverse) {
							skip = true
						}
					case "sport":
						if !MatchFilter(value, config.Filters.SportFilters, config.Filters.SportReverse) {
							skip = true
						}
					case "dport":
						if !MatchFilter(value, config.Filters.DportFilters, config.Filters.DportReverse) {
							skip = true
						}
					case "url":
						if !MatchURLFilter(value, config.Filters) {
							skip = true
						}
					}

					if skip {
						break
					}
				}
				if skip {
					continue
				}
			}
		}

		if config.Filters.SIPFilterMode != 0 || config.Filters.DIPFilterMode != 0 || config.Filters.DomainFilterMode != 0 || config.Filters.SportFilterMode != 0 || config.Filters.DportFilterMode != 0 || config.Filters.URLFilterMode != 0 {
			skip := false

			if config.Filters.SIPFilterMode != 0 {
				isEmpty := fields[1] == "" || fields[1] == "-"
				if (config.Filters.SIPFilterMode == 1 && !isEmpty) || (config.Filters.SIPFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.DIPFilterMode != 0 {
				isEmpty := fields[2] == "" || fields[2] == "-"
				if (config.Filters.DIPFilterMode == 1 && !isEmpty) || (config.Filters.DIPFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.DomainFilterMode != 0 {
				isEmpty := fields[6] == "" || fields[6] == "-"
				if (config.Filters.DomainFilterMode == 1 && !isEmpty) || (config.Filters.DomainFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.SportFilterMode != 0 {
				isEmpty := fields[4] == "" || fields[4] == "-"
				if (config.Filters.SportFilterMode == 1 && !isEmpty) || (config.Filters.SportFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.DportFilterMode != 0 {
				isEmpty := fields[5] == "" || fields[5] == "-"
				if (config.Filters.DportFilterMode == 1 && !isEmpty) || (config.Filters.DportFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.URLFilterMode != 0 {
				isEmpty := fields[7] == "" || fields[7] == "-"
				if (config.Filters.URLFilterMode == 1 && !isEmpty) || (config.Filters.URLFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if skip {
				continue
			}
		}

		if needTimeFilter {
			if !matchTimeRange(fields[9], config.ExportStart, config.ExportEnd) {
				continue
			}
		}

		// 构建安全 record（克隆 unsafe string 为独立副本）
		record := make([]string, 21)
		for i := 0; i < 21; i++ {
			record[i] = strings.Clone(fields[i])
		}

		records = append(records, record)
	}

	return records, scanner.Err()
}

// matchTimeRange 检查UTC时间是否在指定范围内
func matchTimeRange(utcTime, exportStart, exportEnd string) bool {
	if utcTime == "" || utcTime == "-" {
		return false
	}

	normalized := normalizeUTCTime(utcTime)
	if normalized == "" {
		return false
	}

	if exportStart != "" && normalized < exportStart {
		return false
	}
	if exportEnd != "" && normalized > exportEnd {
		return false
	}

	return true
}

// normalizeUTCTime 将日志中的UTC时间标准化为 YYYYMMDDHHmmss 格式
// 支持格式：Unix时间戳(秒/毫秒)、YYYY-MM-DD HH:mm:ss、YYYYMMDDHHmmss 等
func normalizeUTCTime(utcTime string) string {
	utcTime = strings.TrimSpace(utcTime)
	if utcTime == "" || utcTime == "-" {
		return ""
	}

	// 检查是否为Unix时间戳（10位秒级 或 13位毫秒级）
	if isAllDigits(utcTime) && (len(utcTime) == 10 || len(utcTime) == 13) {
		ts, err := strconv.ParseInt(utcTime, 10, 64)
		if err != nil {
			return ""
		}
		// 毫秒级时间戳（13位）
		if len(utcTime) == 13 {
			ts = ts / 1000
		}
		// 转换为本地时间的 YYYYMMDDHHmmss 格式
		return time.Unix(ts, 0).Format("20060102150405")
	}

	if len(utcTime) >= 14 {
		cleaned := strings.NewReplacer("-", "", " ", "", ":", "", "T", "").Replace(utcTime)
		if len(cleaned) >= 14 {
			return cleaned[:14]
		}
	}

	return utcTime
}

// isAllDigits 检查字符串是否全部为数字
func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
