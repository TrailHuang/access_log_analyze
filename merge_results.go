package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// TrafficRecord 存储流量记录
type TrafficRecord struct {
	Rank       int
	DestIP     string
	Domain     string
	UpBytes    int64
	DownBytes  int64
	TotalBytes int64
	RoomName   string
}

// AggregateRecord 聚合记录
type AggregateRecord struct {
	DestIP     string
	Domain     string
	UpBytes    int64
	DownBytes  int64
	TotalBytes int64
	Rooms      map[string]*TrafficRecord
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: go run merge_results.go <结果文件路径>")
		fmt.Println("示例: go run merge_results.go 结果.txt")
		os.Exit(1)
	}

	inputFile := os.Args[1]

	// 检查文件是否存在
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		fmt.Printf("错误: 文件不存在: %s\n", inputFile)
		os.Exit(1)
	}

	fmt.Printf("开始解析文件: %s\n", inputFile)

	// 解析文件
	records, err := parseResultsFile(inputFile)
	if err != nil {
		fmt.Printf("错误: 解析文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("共解析 %d 条记录\n", len(records))

	// 按目的IP+域名聚合
	aggregated := aggregateRecords(records)

	// 转换为切片并排序
	aggList := make([]*AggregateRecord, 0, len(aggregated))
	for _, record := range aggregated {
		aggList = append(aggList, record)
	}

	// 按总流量降序排序
	sort.Slice(aggList, func(i, j int) bool {
		return aggList[i].TotalBytes > aggList[j].TotalBytes
	})

	// 导出CSV
	err = exportToCSV(aggList, "merged_traffic_stats.csv")
	if err != nil {
		fmt.Printf("错误: 导出CSV失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ CSV文件已导出: merged_traffic_stats.csv (共 %d 条记录)\n", len(aggList))
}

// parseResultsFile 解析结果文件
func parseResultsFile(filename string) ([]*TrafficRecord, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	var records []*TrafficRecord
	var currentRoom string

	scanner := bufio.NewScanner(file)
	// 增加buffer大小
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	// 匹配数据行的正则表达式
	// 格式: 1     | 123.180.157.192    | ul-zb.pds.quark.cn                       |    315627363413 |      2317836671 |    317945200084
	dataPattern := regexp.MustCompile(`^\s*\d+\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([\d]+)\s*\|\s*([\d]+)\s*\|\s*([\d]+)\s*$`)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// 跳过空行
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			continue
		}

		// 跳过分隔线
		if strings.Contains(line, "---") {
			continue
		}

		// 跳过表头行
		if strings.Contains(line, "排名") && strings.Contains(line, "目的IP") {
			continue
		}

		// 跳过统计行
		if strings.Contains(line, "Top") && strings.Contains(line, "总计") {
			continue
		}

		// 检测机房名称(不包含"|"和"排名"的行可能是机房名)
		if !strings.Contains(line, "|") && !strings.HasPrefix(trimmedLine, "Top") {
			currentRoom = trimmedLine
			continue
		}

		// 尝试匹配数据行
		matches := dataPattern.FindStringSubmatch(line)
		if matches != nil && currentRoom != "" {
			rank, _ := strconv.Atoi(strings.TrimSpace(strings.Split(line, "|")[0]))
			destIP := strings.TrimSpace(matches[1])
			domain := strings.TrimSpace(matches[2])
			upBytes, _ := strconv.ParseInt(strings.TrimSpace(matches[3]), 10, 64)
			downBytes, _ := strconv.ParseInt(strings.TrimSpace(matches[4]), 10, 64)
			totalBytes, _ := strconv.ParseInt(strings.TrimSpace(matches[5]), 10, 64)

			record := &TrafficRecord{
				Rank:       rank,
				DestIP:     destIP,
				Domain:     domain,
				UpBytes:    upBytes,
				DownBytes:  downBytes,
				TotalBytes: totalBytes,
				RoomName:   currentRoom,
			}
			records = append(records, record)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取文件时出错: %w", err)
	}

	return records, nil
}

// aggregateRecords 按目的IP+域名聚合记录
func aggregateRecords(records []*TrafficRecord) map[string]*AggregateRecord {
	aggregated := make(map[string]*AggregateRecord)

	for _, record := range records {
		key := record.DestIP + "|" + record.Domain

		if agg, exists := aggregated[key]; exists {
			agg.UpBytes += record.UpBytes
			agg.DownBytes += record.DownBytes
			agg.TotalBytes += record.TotalBytes
			agg.Rooms[record.RoomName] = record
		} else {
			aggregated[key] = &AggregateRecord{
				DestIP:     record.DestIP,
				Domain:     record.Domain,
				UpBytes:    record.UpBytes,
				DownBytes:  record.DownBytes,
				TotalBytes: record.TotalBytes,
				Rooms: map[string]*TrafficRecord{
					record.RoomName: record,
				},
			}
		}
	}

	return aggregated
}

// exportToCSV 导出聚合结果到CSV
func exportToCSV(records []*AggregateRecord, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer file.Close()

	// 写入BOM标记
	file.WriteString("\xEF\xBB\xBF")

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	writer.WriteString("排名,目的IP,域名,上行流量(字节),下行流量(字节),总流量(字节),上行流量,下行流量,总流量,涉及的机房\n")

	// 写入数据
	for i, record := range records {
		// 收集涉及的机房
		rooms := make([]string, 0, len(record.Rooms))
		for roomName := range record.Rooms {
			rooms = append(rooms, roomName)
		}
		sort.Strings(rooms)
		roomsStr := strings.Join(rooms, "; ")

		writer.WriteString(fmt.Sprintf("%d,%s,%s,%d,%d,%d,%s,%s,%s,%s\n",
			i+1,
			record.DestIP,
			record.Domain,
			record.UpBytes,
			record.DownBytes,
			record.TotalBytes,
			formatBytes(record.UpBytes),
			formatBytes(record.DownBytes),
			formatBytes(record.TotalBytes),
			roomsStr,
		))
	}

	// 写入总计
	totalUp := int64(0)
	totalDown := int64(0)
	totalAll := int64(0)
	for _, record := range records {
		totalUp += record.UpBytes
		totalDown += record.DownBytes
		totalAll += record.TotalBytes
	}

	writer.WriteString(fmt.Sprintf("\n总计,,,%d,%d,%d,%s,%s,%s,\n",
		totalUp, totalDown, totalAll,
		formatBytes(totalUp), formatBytes(totalDown), formatBytes(totalAll),
	))

	return nil
}

// formatBytes 格式化字节数
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
