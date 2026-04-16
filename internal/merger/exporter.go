package merger

import (
	"access_log_analyze/pkg/models"
	"encoding/csv"
	"fmt"
	"os"
)

// ExportMergedCSV 导出合并后的CSV
func ExportMergedCSV(records []*models.CSVRecord, fieldList []string, outputFile string, sortType string) error {
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

	// 按第一个字段分组排名
	groupField := ""
	if len(fieldList) > 0 {
		groupField = fieldList[0]
	}

	groupRank := make(map[string]int) // 记录每个分组的当前排名

	for _, record := range records {
		// 获取分组key（第一个字段的值）
		groupKey := ""
		if groupField != "" {
			groupKey = record.Fields[groupField]
		}

		// 计算该分组内的排名
		groupRank[groupKey]++
		rank := groupRank[groupKey]

		row := []string{fmt.Sprintf("%d", rank)}
		for _, field := range fieldList {
			row = append(row, record.Fields[field])
		}
		row = append(row,
			fmt.Sprintf("%d", record.UpTotal),
			FormatBytes(record.UpTotal),
			fmt.Sprintf("%d", record.DownTotal),
			FormatBytes(record.DownTotal),
			fmt.Sprintf("%d", record.FlowTotal),
			FormatBytes(record.FlowTotal),
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
		FormatBytes(totalUp),
		fmt.Sprintf("%d", totalDown),
		FormatBytes(totalDown),
		fmt.Sprintf("%d", totalFlow),
		FormatBytes(totalFlow),
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

// FormatBytes 将字节数格式化为人类可读的形式
func FormatBytes(bytes int64) string {
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
