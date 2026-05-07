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
	"strings"
	"sync"
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

	outputPath := config.OutputFile
	if outputPath == "" {
		outputPath = "export_records.csv"
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer file.Close()

	file.WriteString("\xEF\xBB\xBF")

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"HouseId", "源IP", "目的IP", "协议类型", "源端口", "目的端口",
		"域名", "URL", "Duration", "UTC时间", "Title", "流量类型",
		"传输层协议", "应用层协议", "业务层协议", "Referer", "Location",
		"网站内容", "访问数据量", "上行流量", "下行流量", "应用名称",
	}
	if err := writer.Write(header); err != nil {
		return 0, fmt.Errorf("写入CSV表头失败: %w", err)
	}

	var mu sync.Mutex
	var totalExported int64

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

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			localRecords := make([][]string, 0, 10000)

			for filePath := range taskCh {
				records, err := processTarGzForExport(filePath, config)
				if err != nil {
					fmt.Printf("  [Worker %d] 警告: 处理文件 %s 时出错: %v\n", workerID, filepath.Base(filePath), err)
					resultCh <- fileResult{count: 0, err: err}
					continue
				}

				localRecords = append(localRecords, records...)

				if len(localRecords) >= 50000 {
					mu.Lock()
					for _, rec := range localRecords {
						writer.Write(rec)
					}
					totalExported += int64(len(localRecords))
					mu.Unlock()
					localRecords = localRecords[:0]
				}

				fmt.Printf("  [Worker %d] ✓ %s 处理完成，匹配 %d 条记录\n", workerID, filepath.Base(filePath), len(records))
				resultCh <- fileResult{count: int64(len(records)), err: nil}
			}

			if len(localRecords) > 0 {
				mu.Lock()
				for _, rec := range localRecords {
					writer.Write(rec)
				}
				totalExported += int64(len(localRecords))
				mu.Unlock()
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for res := range resultCh {
		_ = res
	}

	return totalExported, nil
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

		if len(positions) < 22 {
			continue
		}

		if needFilter {
			skip := false
			for _, ff := range filterFields {
				value := getFieldString(lineBytes, positions, ff.idx)

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

		if config.Filters.SIPFilterMode != 0 || config.Filters.DIPFilterMode != 0 || config.Filters.DomainFilterMode != 0 || config.Filters.SportFilterMode != 0 || config.Filters.DportFilterMode != 0 || config.Filters.URLFilterMode != 0 {
			skip := false

			if config.Filters.SIPFilterMode != 0 {
				value := getFieldString(lineBytes, positions, 1)
				isEmpty := value == "" || value == "-"
				if (config.Filters.SIPFilterMode == 1 && !isEmpty) || (config.Filters.SIPFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.DIPFilterMode != 0 {
				value := getFieldString(lineBytes, positions, 2)
				isEmpty := value == "" || value == "-"
				if (config.Filters.DIPFilterMode == 1 && !isEmpty) || (config.Filters.DIPFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.DomainFilterMode != 0 {
				value := getFieldString(lineBytes, positions, 6)
				isEmpty := value == "" || value == "-"
				if (config.Filters.DomainFilterMode == 1 && !isEmpty) || (config.Filters.DomainFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.SportFilterMode != 0 {
				value := getFieldString(lineBytes, positions, 4)
				isEmpty := value == "" || value == "-"
				if (config.Filters.SportFilterMode == 1 && !isEmpty) || (config.Filters.SportFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.DportFilterMode != 0 {
				value := getFieldString(lineBytes, positions, 5)
				isEmpty := value == "" || value == "-"
				if (config.Filters.DportFilterMode == 1 && !isEmpty) || (config.Filters.DportFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && config.Filters.URLFilterMode != 0 {
				value := getFieldString(lineBytes, positions, 7)
				isEmpty := value == "" || value == "-"
				if (config.Filters.URLFilterMode == 1 && !isEmpty) || (config.Filters.URLFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if skip {
				continue
			}
		}

		if needTimeFilter {
			utcTime := getFieldString(lineBytes, positions, 9)
			if !matchTimeRange(utcTime, config.ExportStart, config.ExportEnd) {
				continue
			}
		}

		record := make([]string, 22)
		for i := 0; i < 22 && i < len(positions); i++ {
			record[i] = getFieldString(lineBytes, positions, i)
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
func normalizeUTCTime(utcTime string) string {
	utcTime = strings.TrimSpace(utcTime)
	if utcTime == "" || utcTime == "-" {
		return ""
	}

	if len(utcTime) >= 14 {
		cleaned := strings.NewReplacer("-", "", " ", "", ":", "", "T", "").Replace(utcTime)
		if len(cleaned) >= 14 {
			return cleaned[:14]
		}
	}

	return utcTime
}
