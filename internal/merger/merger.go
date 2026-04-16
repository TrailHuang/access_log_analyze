package merger

import (
	"access_log_analyze/pkg/models"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// MergeCSVFiles 合并目录下所有up/down/total CSV文件
func MergeCSVFiles(dirPath string, fieldsStr string, topN int, durationSeconds float64) error {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return fmt.Errorf("目录不存在: %s", dirPath)
	}

	fieldList := strings.Split(fieldsStr, ",")
	for i, f := range fieldList {
		fieldList[i] = strings.TrimSpace(f)
	}

	fmt.Printf("开始合并目录: %s\n", dirPath)
	fmt.Printf("合并字段: %s\n", fieldsStr)

	var csvFiles []string
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".csv") {
			csvFiles = append(csvFiles, path)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("遍历目录失败: %v", err)
	}

	fmt.Printf("找到 %d 个CSV文件\n", len(csvFiles))

	upFiles, downFiles, totalFiles := classifyFiles(csvFiles)
	fmt.Printf("up文件: %d 个, down文件: %d 个, total文件: %d 个\n", len(upFiles), len(downFiles), len(totalFiles))

	if len(upFiles) > 0 {
		fmt.Println("\n========== 合并 up 数据 ==========")
		if err := mergeCSVFilesByType(upFiles, fieldList, "up", topN, durationSeconds); err != nil {
			return fmt.Errorf("合并up文件失败: %v", err)
		}
	}

	if len(downFiles) > 0 {
		fmt.Println("\n========== 合并 down 数据 ==========")
		if err := mergeCSVFilesByType(downFiles, fieldList, "down", topN, durationSeconds); err != nil {
			return fmt.Errorf("合并down文件失败: %v", err)
		}
	}

	if len(totalFiles) > 0 {
		fmt.Println("\n========== 合并 total 数据 ==========")
		if err := mergeCSVFilesByType(totalFiles, fieldList, "total", topN, durationSeconds); err != nil {
			return fmt.Errorf("合并total文件失败: %v", err)
		}
	}

	return nil
}

func classifyFiles(files []string) (upFiles, downFiles, totalFiles []string) {
	for _, file := range files {
		name := strings.ToLower(filepath.Base(file))
		if strings.Contains(name, "_up.csv") || strings.HasSuffix(name, "up.csv") {
			upFiles = append(upFiles, file)
		} else if strings.Contains(name, "_down.csv") || strings.HasSuffix(name, "down.csv") {
			downFiles = append(downFiles, file)
		} else if strings.Contains(name, "_total.csv") || strings.HasSuffix(name, "total.csv") {
			totalFiles = append(totalFiles, file)
		}
	}
	return
}

func mergeCSVFilesByType(files []string, fieldList []string, sortType string, topN int, durationSeconds float64) error {
	aggregated := make(map[string]*models.CSVRecord)
	filesProcessed := 0

	for _, file := range files {
		fmt.Printf("  读取: %s\n", filepath.Base(file))

		f, err := os.Open(file)
		if err != nil {
			fmt.Printf("    警告: 打开文件失败: %v\n", err)
			continue
		}

		reader := csv.NewReader(f)
		reader.LazyQuotes = true

		headers, err := reader.Read()
		if err != nil {
			f.Close()
			fmt.Printf("    警告: 读取表头失败: %v\n", err)
			continue
		}

		fieldIndex := make(map[string]int)
		for i, h := range headers {
			h = strings.TrimSpace(h)
			if i == 0 {
				h = strings.TrimPrefix(h, "\xEF\xBB\xBF")
			}
			fieldIndex[h] = i
		}

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

			if len(record) > 0 && (record[0] == "总计" || record[0] == "排名") {
				continue
			}

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

			upBytes := parseInt64(record, fieldIndex, "上行流量(字节)")
			downBytes := parseInt64(record, fieldIndex, "下行流量(字节)")
			totalBytes := parseInt64(record, fieldIndex, "总流量(字节)")
			flowCount := parseInt64(record, fieldIndex, "流数")

			if agg, exists := aggregated[key]; exists {
				agg.UpTotal += upBytes
				agg.DownTotal += downBytes
				agg.FlowTotal += totalBytes
				agg.FlowCount += flowCount
			} else {
				aggregated[key] = &models.CSVRecord{
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

	records := make([]*models.CSVRecord, 0, len(aggregated))
	for _, record := range aggregated {
		records = append(records, record)
	}

	sort.Slice(records, func(i, j int) bool {
		switch sortType {
		case "down":
			return records[i].DownTotal > records[j].DownTotal
		case "total":
			return records[i].FlowTotal > records[j].FlowTotal
		default:
			return records[i].UpTotal > records[j].UpTotal
		}
	})

	outputFile := fmt.Sprintf("merged_%s.csv", sortType)
	if err := ExportMergedCSV(records, fieldList, outputFile, sortType, durationSeconds); err != nil {
		return fmt.Errorf("导出CSV失败: %v", err)
	}

	if len(fieldList) >= 2 {
		fmt.Printf("  提取每个 %s 的 Top%d...\n", fieldList[0], topN)
		if err := extractTopNPerKey(records, fieldList, sortType, topN, durationSeconds); err != nil {
			return fmt.Errorf("提取Top%d失败: %v", topN, err)
		}
	}

	return nil
}

func parseInt64(record []string, fieldIndex map[string]int, fieldName string) int64 {
	if idx, ok := fieldIndex[fieldName]; ok && idx < len(record) {
		val := strings.TrimSpace(record[idx])
		val = strings.ReplaceAll(val, ",", "")
		if v, err := strconv.ParseInt(val, 10, 64); err == nil {
			return v
		}
	}
	return 0
}

func extractTopNPerKey(records []*models.CSVRecord, fieldList []string, sortType string, topN int, durationSeconds float64) error {
	if len(fieldList) < 2 {
		return fmt.Errorf("至少需要2个字段才能提取TopN")
	}

	groupField := fieldList[0]
	groups := make(map[string][]*models.CSVRecord)
	for _, record := range records {
		key := record.Fields[groupField]
		groups[key] = append(groups[key], record)
	}

	var topNRecords []*models.CSVRecord
	for _, groupRecords := range groups {
		copiedRecords := make([]*models.CSVRecord, len(groupRecords))
		for i, r := range groupRecords {
			copiedRecords[i] = &models.CSVRecord{
				Key:       r.Key,
				Fields:    r.Fields,
				UpTotal:   r.UpTotal,
				DownTotal: r.DownTotal,
				FlowTotal: r.FlowTotal,
				FlowCount: r.FlowCount,
			}
		}

		sort.Slice(copiedRecords, func(i, j int) bool {
			switch sortType {
			case "down":
				return copiedRecords[i].DownTotal > copiedRecords[j].DownTotal
			case "total":
				return copiedRecords[i].FlowTotal > copiedRecords[j].FlowTotal
			default:
				return copiedRecords[i].UpTotal > copiedRecords[j].UpTotal
			}
		})

		limit := topN
		if len(copiedRecords) < limit {
			limit = len(copiedRecords)
		}
		topNRecords = append(topNRecords, copiedRecords[:limit]...)
	}

	sort.Slice(topNRecords, func(i, j int) bool {
		keyI := topNRecords[i].Fields[groupField]
		keyJ := topNRecords[j].Fields[groupField]

		if keyI != keyJ {
			return keyI < keyJ
		}

		switch sortType {
		case "down":
			return topNRecords[i].DownTotal > topNRecords[j].DownTotal
		case "total":
			return topNRecords[i].FlowTotal > topNRecords[j].FlowTotal
		default:
			return topNRecords[i].UpTotal > topNRecords[j].UpTotal
		}
	})

	outputFile := fmt.Sprintf("top%d_%s.csv", topN, sortType)
	if err := ExportMergedCSV(topNRecords, fieldList, outputFile, sortType, durationSeconds); err != nil {
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
