package analyzer

import (
	"access_log_analyze/pkg/models"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"
)

// PrintResultsFromMap 从map输出统计结果
func PrintResultsFromMap(statsMap map[string]*models.TrafficStats, fieldIndexes map[string]int, topN int, sortBy string, csvTop int, outputFile string) {
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
