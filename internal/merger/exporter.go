package merger

import (
	"access_log_analyze/pkg/models"
	"encoding/csv"
	"fmt"
	"os"
)

// ExportMergedCSV 导出合并后的CSV
func ExportMergedCSV(records []*models.CSVRecord, fieldList []string, outputFile string, sortType string, durationSeconds float64, output string) error {
	if durationSeconds <= 0 {
		durationSeconds = 1 // 防止除零，默认1秒
	}

	singleField := len(fieldList) == 1

	if output == "" {
		output = "."
	} else {
		if _, err := os.Stat(output); os.IsNotExist(err) {
			if err := os.MkdirAll(output, 0755); err != nil {
				return fmt.Errorf("创建输出目录失败: %v", err)
			}
		}
	}
	file, err := os.Create(output + "/" + outputFile)
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
	header = append(header, "上行流量(字节)", "上行流量", "上行Gbps", "上行占比", "下行流量(字节)", "下行流量", "下行Gbps", "下行占比", "总流量(字节)", "总流量", "总Gbps", "总流量占比", "流数")
	writer.Write(header)

	// 按第一个字段分组排名
	groupField := ""
	if len(fieldList) > 0 {
		groupField = fieldList[0]
	}

	// 预计算每个分组的汇总流量，用于计算占比
	groupUpTotal := make(map[string]int64)
	groupDownTotal := make(map[string]int64)
	groupTotalBytes := make(map[string]int64)
	groupFlowCount := make(map[string]int64)

	for _, record := range records {
		groupKey := ""
		if groupField != "" {
			groupKey = record.Fields[groupField]
		}
		groupUpTotal[groupKey] += record.UpTotal
		groupDownTotal[groupKey] += record.DownTotal
		groupTotalBytes[groupKey] += record.FlowTotal
		groupFlowCount[groupKey] += record.FlowCount
	}

	// 全局总计
	totalUp := int64(0)
	totalDown := int64(0)
	totalFlow := int64(0)
	totalFlowCount := int64(0)
	for _, v := range groupUpTotal {
		totalUp += v
	}
	for _, v := range groupDownTotal {
		totalDown += v
	}
	for _, v := range groupTotalBytes {
		totalFlow += v
	}
	for _, v := range groupFlowCount {
		totalFlowCount += v
	}

	groupRank := make(map[string]int) // 记录每个分组的当前排名
	var lastGroupKey string           // 记录上一个分组的key
	globalRank := 0                   // 单字段模式下的全局连续排名

	for _, record := range records {
		// 获取分组key（第一个字段的值）
		groupKey := ""
		if groupField != "" {
			groupKey = record.Fields[groupField]
		}

		// 检测到新的分组，写入上一个分组的汇总行（仅多字段模式）
		if !singleField && lastGroupKey != "" && groupKey != lastGroupKey {
			writeGroupSummary(writer, lastGroupKey, fieldList, groupUpTotal, groupDownTotal, groupTotalBytes, groupFlowCount, durationSeconds)
		}

		// 计算排名：单字段模式用连续排名，多字段模式按分组排名
		var rank int
		if singleField {
			globalRank++
			rank = globalRank
		} else {
			groupRank[groupKey]++
			rank = groupRank[groupKey]
		}

		// 计算Gbps (bits per second / 1,000,000,000)
		upGbps := float64(record.UpTotal*8) / durationSeconds / 1000000000
		downGbps := float64(record.DownTotal*8) / durationSeconds / 1000000000
		totalGbps := float64(record.FlowTotal*8) / durationSeconds / 1000000000

		// 计算占比：单字段模式按全局总计，多字段模式按分组汇总
		var upPercent, downPercent, totalPercent string
		if singleField {
			upPercent = formatPercent(record.UpTotal, totalUp)
			downPercent = formatPercent(record.DownTotal, totalDown)
			totalPercent = formatPercent(record.FlowTotal, totalFlow)
		} else {
			upPercent = formatPercent(record.UpTotal, groupUpTotal[groupKey])
			downPercent = formatPercent(record.DownTotal, groupDownTotal[groupKey])
			totalPercent = formatPercent(record.FlowTotal, groupTotalBytes[groupKey])
		}

		row := []string{fmt.Sprintf("%d", rank)}
		for _, field := range fieldList {
			row = append(row, record.Fields[field])
		}
		row = append(row,
			fmt.Sprintf("%d", record.UpTotal),
			models.FormatBytes(record.UpTotal),
			fmt.Sprintf("%.2f", upGbps),
			upPercent,
			fmt.Sprintf("%d", record.DownTotal),
			models.FormatBytes(record.DownTotal),
			fmt.Sprintf("%.2f", downGbps),
			downPercent,
			fmt.Sprintf("%d", record.FlowTotal),
			models.FormatBytes(record.FlowTotal),
			fmt.Sprintf("%.2f", totalGbps),
			totalPercent,
			fmt.Sprintf("%d", record.FlowCount),
		)
		writer.Write(row)

		// 更新上一个分组key
		lastGroupKey = groupKey
	}

	// 写入最后一个分组的汇总行（仅多字段模式）
	if !singleField && lastGroupKey != "" {
		writeGroupSummary(writer, lastGroupKey, fieldList, groupUpTotal, groupDownTotal, groupTotalBytes, groupFlowCount, durationSeconds)
	}

	// 写入总计行（仅多字段模式）
	if !singleField {
		totalUpGbps := float64(totalUp*8) / durationSeconds / 1000000000
		totalDownGbps := float64(totalDown*8) / durationSeconds / 1000000000
		totalFlowGbps := float64(totalFlow*8) / durationSeconds / 1000000000

		totalRow := []string{"总计"}
		for i := 0; i < len(fieldList); i++ {
			totalRow = append(totalRow, "")
		}
		totalRow = append(totalRow,
			fmt.Sprintf("%d", totalUp),
			models.FormatBytes(totalUp),
			fmt.Sprintf("%.2f", totalUpGbps),
			"100.00%",
			fmt.Sprintf("%d", totalDown),
			models.FormatBytes(totalDown),
			fmt.Sprintf("%.2f", totalDownGbps),
			"100.00%",
			fmt.Sprintf("%d", totalFlow),
			models.FormatBytes(totalFlow),
			fmt.Sprintf("%.2f", totalFlowGbps),
			"100.00%",
			fmt.Sprintf("%d", totalFlowCount),
		)
		writer.Write(totalRow)
	}

	sortLabel := map[string]string{"up": "上行流量", "down": "下行流量", "total": "总流量"}
	label := sortLabel[sortType]
	if label == "" {
		label = sortType
	}

	fmt.Printf("  ✓ [%s] 合并结果已导出: %s (共 %d 条记录)\n", label, outputFile, len(records))

	return nil
}

// formatPercent 计算占比并格式化为百分比字符串
func formatPercent(part, total int64) string {
	if total == 0 {
		return "0.00%"
	}
	return fmt.Sprintf("%.2f%%", float64(part)/float64(total)*100)
}

// writeGroupSummary 写入分组汇总行
func writeGroupSummary(writer *csv.Writer, groupKey string, fieldList []string, groupUpTotal, groupDownTotal, groupTotalBytes, groupFlowCount map[string]int64, durationSeconds float64) {
	upGbps := float64(groupUpTotal[groupKey]*8) / durationSeconds / 1000000000
	downGbps := float64(groupDownTotal[groupKey]*8) / durationSeconds / 1000000000
	totalGbps := float64(groupTotalBytes[groupKey]*8) / durationSeconds / 1000000000

	summaryRow := []string{"汇总"}
	// 填充字段列（第一个字段显示IP，其他留空）
	for i := 0; i < len(fieldList); i++ {
		if i == 0 {
			summaryRow = append(summaryRow, groupKey)
		} else {
			summaryRow = append(summaryRow, "")
		}
	}
	summaryRow = append(summaryRow,
		fmt.Sprintf("%d", groupUpTotal[groupKey]),
		models.FormatBytes(groupUpTotal[groupKey]),
		fmt.Sprintf("%.2f", upGbps),
		"100.00%",
		fmt.Sprintf("%d", groupDownTotal[groupKey]),
		models.FormatBytes(groupDownTotal[groupKey]),
		fmt.Sprintf("%.2f", downGbps),
		"100.00%",
		fmt.Sprintf("%d", groupTotalBytes[groupKey]),
		models.FormatBytes(groupTotalBytes[groupKey]),
		fmt.Sprintf("%.2f", totalGbps),
		"100.00%",
		fmt.Sprintf("%d", groupFlowCount[groupKey]),
	)
	writer.Write(summaryRow)
}

// PrintHelp 打印帮助信息
func PrintHelp() {
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
	fmt.Println("")
	fmt.Println("排序参数:")
	fmt.Println("  -sort      排序方式: up(上行流量), down(下行流量), total(总流量)")
	fmt.Println("           支持逗号分隔多个值,为每个排序方式生成独立的表格和CSV文件")
	fmt.Println("")
	fmt.Println("CSV合并:")
	fmt.Println("  -merge     合并目录路径，将目录下所有up/down/total CSV文件按fields合并")
	fmt.Println("  -top       合并时每个分组提取的Top N条记录(默认10)")
	fmt.Println("  示例: ./access_log_analyzer -merge /path/to/csv_dir -fields \"dip,domain\" -top 10")
	fmt.Println("        会生成: merged_up.csv, merged_down.csv, top10_up.csv, top10_down.csv")
}
