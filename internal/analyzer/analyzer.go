package analyzer

import (
	"access_log_analyze/pkg/models"
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"archive/tar"
	"io"

	"github.com/olekukonko/tablewriter"
)

// Pool 对象池配置
var (
	// fieldValuesPool 复用 map[string]string，预分配容量30
	FieldValuesPool = sync.Pool{
		New: func() interface{} {
			return make(map[string]string, 30)
		},
	}

	// keyPartsPool 复用 []string，预分配容量20
	KeyPartsPool = sync.Pool{
		New: func() interface{} {
			return make([]string, 0, 20)
		},
	}

	// keyBuilderPool 复用 strings.Builder 用于构建key
	KeyBuilderPool = sync.Pool{
		New: func() interface{} {
			return &strings.Builder{}
		},
	}
)

// ProcessTarGz 处理单个tar.gz文件
func ProcessTarGz(filePath string, statsMap map[string]*models.TrafficStats, fieldIndexes map[string]int, filters *models.LogFilters) error {
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
func processLogFile(reader io.Reader, statsMap map[string]*models.TrafficStats, fieldIndexes map[string]int, filters *models.LogFilters) error {
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
		fields := strings.Split(line, "|")

		if len(fields) < 20 {
			continue
		}

		// 优化3: 使用sync.Pool复用对象，减少GC压力
		keyParts := KeyPartsPool.Get().([]string)
		keyParts = keyParts[:0]

		fieldValues := FieldValuesPool.Get().(map[string]string)
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

		// 优化4: 使用strings.Builder复用对象构建key
		keyBuilder := KeyBuilderPool.Get().(*strings.Builder)
		keyBuilder.Reset()

		totalLen := 0
		for i, part := range keyParts {
			totalLen += len(part)
			if i < len(keyParts)-1 {
				totalLen++
			}
		}
		keyBuilder.Grow(totalLen)

		for i, part := range keyParts {
			if i > 0 {
				keyBuilder.WriteByte('|')
			}
			keyBuilder.WriteString(part)
		}
		key := keyBuilder.String()
		KeyBuilderPool.Put(keyBuilder)

		// 应用过滤条件
		sip := fieldValues["sip"]
		dip := fieldValues["dip"]
		domain := fieldValues["domain"]

		if !MatchFilter(sip, filters.SIPFilters) || !MatchFilter(dip, filters.DIPFilters) || !MatchFilter(domain, filters.DomainFilters) {
			KeyPartsPool.Put(keyParts)
			FieldValuesPool.Put(fieldValues)
			continue
		}

		// 提取上行流量 (索引18) 和 下行流量 (索引19)
		upTraffic, _ := strconv.ParseInt(strings.TrimSpace(fields[18]), 10, 64)
		downTraffic, _ := strconv.ParseInt(strings.TrimSpace(fields[19]), 10, 64)

		// 更新统计
		if stats, exists := statsMap[key]; exists {
			stats.UpTotal += upTraffic
			stats.DownTotal += downTraffic
			stats.FlowTotal++
			KeyPartsPool.Put(keyParts)
			FieldValuesPool.Put(fieldValues)
		} else {
			fieldValuesCopy := make(map[string]string, len(fieldValues))
			for k, v := range fieldValues {
				fieldValuesCopy[k] = v
			}
			statsMap[key] = &models.TrafficStats{
				Key:       key,
				Fields:    fieldValuesCopy,
				UpTotal:   upTraffic,
				DownTotal: downTraffic,
				FlowTotal: 1,
			}
			KeyPartsPool.Put(keyParts)
			FieldValuesPool.Put(fieldValues)
		}
	}

	return scanner.Err()
}

// ProcessFilesConcurrent 并发处理多个tar.gz文件
func ProcessFilesConcurrent(files []string, fieldIndexes map[string]int, filters *models.LogFilters, numWorkers int, batchSize int, outputBaseName string) map[string]*models.TrafficStats {
	if numWorkers > len(files) {
		numWorkers = len(files)
	}
	if numWorkers == 0 {
		return make(map[string]*models.TrafficStats)
	}

	fmt.Printf("使用 %d 个协程并发处理，每 %d 个文件生成一次临时CSV\n", numWorkers, batchSize)

	taskCh := make(chan string, len(files))
	for _, file := range files {
		taskCh <- file
	}
	close(taskCh)

	type result struct {
		stats map[string]*models.TrafficStats
		err   error
	}
	resultCh := make(chan result, len(files))

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			localStats := make(map[string]*models.TrafficStats)
			fileCount := 0

			for filePath := range taskCh {
				fileCount++
				fileStart := time.Now()
				fileName := filepath.Base(filePath)

				err := ProcessTarGz(filePath, localStats, fieldIndexes, filters)
				fileDuration := time.Since(fileStart)

				if err != nil {
					fmt.Printf("  [Worker %d] 警告: 处理文件 %s 时出错: %v (%.2fs)\n", workerID, fileName, err, fileDuration.Seconds())
				} else {
					fmt.Printf("  [Worker %d] ✓ %s 处理完成 (%.2fs)\n", workerID, fileName, fileDuration.Seconds())
				}

				if batchSize > 0 && fileCount%batchSize == 0 {
					GenerateTempCSV(localStats, fieldIndexes, outputBaseName, workerID, fileCount)
				}

				resultCh <- result{stats: nil, err: err}
			}

			if len(localStats) > 0 {
				if batchSize > 0 {
					GenerateTempCSV(localStats, fieldIndexes, outputBaseName, workerID, fileCount)
				}

				statsCopy := make(map[string]*models.TrafficStats, len(localStats))
				for key, stats := range localStats {
					fieldValuesCopy := make(map[string]string, len(stats.Fields))
					for k, v := range stats.Fields {
						fieldValuesCopy[k] = v
					}
					statsCopy[key] = &models.TrafficStats{
						Key:       stats.Key,
						Fields:    fieldValuesCopy,
						UpTotal:   stats.UpTotal,
						DownTotal: stats.DownTotal,
						FlowTotal: stats.FlowTotal,
					}
				}
				resultCh <- result{stats: statsCopy, err: nil}
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	finalStats := make(map[string]*models.TrafficStats)
	processedFiles := 0

	for res := range resultCh {
		if res.stats != nil {
			mergeStats(finalStats, res.stats)
			continue // stats消息不计入文件进度
		}

		processedFiles++
		if processedFiles%10 == 0 || processedFiles == len(files) {
			fmt.Printf("\r已处理: %d/%d 文件", processedFiles, len(files))
		}
	}
	fmt.Println()

	return finalStats
}

// mergeStats 合并统计结果
func mergeStats(dst, src map[string]*models.TrafficStats) {
	for key, srcStats := range src {
		if dstStats, exists := dst[key]; exists {
			dstStats.UpTotal += srcStats.UpTotal
			dstStats.DownTotal += srcStats.DownTotal
			dstStats.FlowTotal += srcStats.FlowTotal
		} else {
			dst[key] = &models.TrafficStats{
				Key:       srcStats.Key,
				Fields:    srcStats.Fields,
				UpTotal:   srcStats.UpTotal,
				DownTotal: srcStats.DownTotal,
				FlowTotal: srcStats.FlowTotal,
			}
		}
	}
}

// GenerateTempCSV 生成临时CSV文件
func GenerateTempCSV(statsMap map[string]*models.TrafficStats, fieldIndexes map[string]int, outputBaseName string, workerID int, fileCount int) {
	if len(statsMap) == 0 {
		return
	}

	var tempFileName string
	if outputBaseName == "" {
		tempFileName = fmt.Sprintf("traffic_stats_worker%d_1-%d.csv", workerID, fileCount)
	} else {
		baseName := strings.TrimSuffix(outputBaseName, filepath.Ext(outputBaseName))
		ext := filepath.Ext(outputBaseName)
		if ext == "" {
			ext = ".csv"
		}
		tempFileName = fmt.Sprintf("%s_worker%d_1-%d%s", baseName, workerID, fileCount, ext)
	}

	statsList := make([]*models.TrafficStats, 0, len(statsMap))
	for _, stats := range statsMap {
		statsList = append(statsList, stats)
	}

	sort.Slice(statsList, func(i, j int) bool {
		return (statsList[i].UpTotal + statsList[i].DownTotal) > (statsList[j].UpTotal + statsList[j].DownTotal)
	})

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

	file, err := os.Create(tempFileName)
	if err != nil {
		fmt.Printf("\n  [Worker %d] 错误: 创建临时CSV文件失败 %s: %v\n", workerID, tempFileName, err)
		return
	}
	defer file.Close()

	file.WriteString("\xEF\xBB\xBF")
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	writer.WriteString("排名")
	for _, fp := range sortedFields {
		writer.WriteString("," + fp.name)
	}
	writer.WriteString(",上行流量(字节),上行流量,下行流量(字节),下行流量,总流量(字节),总流量,流数\n")

	for i, stats := range statsList {
		writer.WriteString(fmt.Sprintf("%d", i+1))
		for _, fp := range sortedFields {
			value := stats.Fields[fp.name]
			if strings.Contains(value, ",") || strings.Contains(value, "\"") {
				value = "\"" + strings.ReplaceAll(value, "\"", "\"\"") + "\""
			}
			writer.WriteString("," + value)
		}
		writer.WriteString(fmt.Sprintf(",%d,%s,%d,%s,%d,%s,%d\n",
			stats.UpTotal,
			models.FormatBytes(stats.UpTotal),
			stats.DownTotal,
			models.FormatBytes(stats.DownTotal),
			stats.UpTotal+stats.DownTotal,
			models.FormatBytes(stats.UpTotal+stats.DownTotal),
			stats.FlowTotal,
		))
	}

	fmt.Printf("  [Worker %d] ✓ 临时CSV已生成: %s (已处理 %d 个文件, %d 条记录)\n", workerID, tempFileName, fileCount, len(statsList))
}

// PrintResults 输出统计结果
func PrintResults(statsMap map[string]*models.TrafficStats, fieldIndexes map[string]int, topN int, sortBy string, csvTop int, outputFile string) {
	statsList := make([]*models.TrafficStats, 0, len(statsMap))
	for _, stats := range statsMap {
		statsList = append(statsList, stats)
	}

	sortTypes := strings.Split(sortBy, ",")
	for i, st := range sortTypes {
		sortTypes[i] = strings.TrimSpace(st)
	}
	seen := make(map[string]bool)
	uniqueSortTypes := []string{}
	for _, st := range sortTypes {
		if !seen[st] {
			seen[st] = true
			uniqueSortTypes = append(uniqueSortTypes, st)
		}
	}
	sortTypes = uniqueSortTypes

	for _, sortType := range sortTypes {
		sortedList := make([]*models.TrafficStats, len(statsList))
		copy(sortedList, statsList)

		sort.Slice(sortedList, func(i, j int) bool {
			switch sortType {
			case "down":
				return sortedList[i].DownTotal > sortedList[j].DownTotal
			case "total":
				return (sortedList[i].UpTotal + sortedList[i].DownTotal) > (sortedList[j].UpTotal + sortedList[j].DownTotal)
			default:
				return sortedList[i].UpTotal > sortedList[j].UpTotal
			}
		})

		displayCount := topN
		if len(sortedList) < displayCount {
			displayCount = len(sortedList)
		}

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

		sortLabel := map[string]string{"up": "上行流量", "down": "下行流量", "total": "总流量"}
		label := sortLabel[sortType]
		if label == "" {
			label = sortType
		}
		fmt.Printf("\n========== 按%s排序 ==========\n", label)

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
				models.FormatBytes(stats.UpTotal),
				fmt.Sprintf("%d", stats.DownTotal),
				models.FormatBytes(stats.DownTotal),
				fmt.Sprintf("%d", totalBytes),
				models.FormatBytes(totalBytes),
				fmt.Sprintf("%d", stats.FlowTotal),
			)
			table.Append(row)
			totalUp += stats.UpTotal
			totalDown += stats.DownTotal
			totalFlow += stats.FlowTotal
		}

		totalAll := totalUp + totalDown
		totalRow := []string{"总计"}
		for i := 0; i < len(fieldIndexes); i++ {
			totalRow = append(totalRow, "")
		}
		totalRow = append(totalRow,
			fmt.Sprintf("%d", totalUp),
			models.FormatBytes(totalUp),
			fmt.Sprintf("%d", totalDown),
			models.FormatBytes(totalDown),
			fmt.Sprintf("%d", totalAll),
			models.FormatBytes(totalAll),
			fmt.Sprintf("%d", totalFlow),
		)
		table.Append(totalRow)

		fmt.Println()
		table.Render()
		fmt.Printf("\n共 %d 个唯一组合, 显示 Top %d\n", len(statsMap), displayCount)

		ExportToCSV(sortedList, fieldIndexes, csvTop, outputFile, sortType)
	}
}

// ExportToCSV 导出完整的统计结果到CSV文件
func ExportToCSV(statsList []*models.TrafficStats, fieldIndexes map[string]int, csvTop int, outputFile string, sortType string) {
	if outputFile == "" {
		timestamp := time.Now().Format("20060102_150405")
		outputFile = fmt.Sprintf("traffic_stats_%s.csv", timestamp)
	}

	baseName := strings.TrimSuffix(outputFile, filepath.Ext(outputFile))
	ext := filepath.Ext(outputFile)
	csvFileName := fmt.Sprintf("%s_%s%s", baseName, sortType, ext)

	file, err := os.Create(csvFileName)
	if err != nil {
		fmt.Printf("\n错误: 创建CSV文件失败: %v\n", err)
		return
	}
	defer file.Close()

	file.WriteString("\xEF\xBB\xBF")
	writer := bufio.NewWriter(file)
	defer writer.Flush()

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

	writer.WriteString("排名")
	for _, fp := range sortedFields {
		writer.WriteString("," + fp.name)
	}
	writer.WriteString(",上行流量(字节),上行流量,下行流量(字节),下行流量,总流量(字节),总流量,流数\n")

	exportCount := len(statsList)
	if csvTop > 0 && csvTop < exportCount {
		exportCount = csvTop
	}

	for i := 0; i < exportCount; i++ {
		stats := statsList[i]
		writer.WriteString(fmt.Sprintf("%d", i+1))
		for _, fp := range sortedFields {
			value := stats.Fields[fp.name]
			if strings.Contains(value, ",") || strings.Contains(value, "\"") {
				value = "\"" + strings.ReplaceAll(value, "\"", "\"\"") + "\""
			}
			writer.WriteString("," + value)
		}
		writer.WriteString(fmt.Sprintf(",%d,%s,%d,%s,%d,%s,%d\n",
			stats.UpTotal,
			models.FormatBytes(stats.UpTotal),
			stats.DownTotal,
			models.FormatBytes(stats.DownTotal),
			stats.UpTotal+stats.DownTotal,
			models.FormatBytes(stats.UpTotal+stats.DownTotal),
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

