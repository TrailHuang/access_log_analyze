package analyzer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ExtractTimeFromFileName 从文件名中提取时间信息
// 支持格式：log_20260331_success.tar.gz 或 access_log_20260330062627638743.tar.gz
// 提取后统一补齐到秒精度（14位：YYYYMMDDHHmmss）
func ExtractTimeFromFileName(fileName string) string {
	// 去除扩展名
	baseName := strings.TrimSuffix(fileName, ".tar.gz")
	baseName = strings.TrimSuffix(baseName, ".gz")

	// 使用正则表达式匹配所有8位或更多数字的序列
	re := regexp.MustCompile(`\d{8,}`)
	matches := re.FindAllString(baseName, -1)

	if len(matches) == 0 {
		return ""
	}

	// 选择最长的数字串作为时间（时间戳通常是最长的数字串）
	timeStr := matches[0]
	for _, match := range matches {
		if len(match) > len(timeStr) {
			timeStr = match
		}
	}

	// 将时间字符串处理到14位（秒精度）
	// YYYYMMDDHHmmss... -> 截断到秒（14位）
	if len(timeStr) >= 14 {
		return timeStr[:14]
	}
	// 如果不足14位，说明不是有效的时间格式
	return ""
}

// ParseTime 解析时间字符串为int64，必须是14位秒精度（YYYYMMDDHHmmss）
func ParseTime(timeStr string) (int64, error) {
	if timeStr == "" {
		return 0, nil
	}

	// 移除可能的空格
	timeStr = strings.TrimSpace(timeStr)

	// 验证格式：必须是14位数字
	if len(timeStr) != 14 {
		return 0, fmt.Errorf("无效的时间格式: %s (必须为14位，格式: YYYYMMDDHHmmss，例如: 20260330062627)", timeStr)
	}

	// 转换为整数
	t, err := strconv.ParseInt(timeStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("无效的时间格式: %s", timeStr)
	}

	return t, nil
}

// IsFileInTimeRange 检查文件是否在时间范围内
// startTime和endTime都应该是14位秒精度
func IsFileInTimeRange(fileName string, startTime int64, endTime int64) bool {
	// 从文件名提取时间（已经是14位秒精度）
	fileTimeStr := ExtractTimeFromFileName(fileName)
	if fileTimeStr == "" {
		// 无法提取时间，不过滤
		return true
	}
	fileTime, err := ParseTime(fileTimeStr)
	if err != nil {
		// 解析失败，不过滤
		return true
	}

	// 检查时间范围（都是14位秒精度，直接比较）
	if startTime > 0 && fileTime < startTime {
		return false
	}
	if endTime > 0 && fileTime > endTime {
		return false
	}

	return true
}

// ParseFieldNames 解析字段名到索引的映射
func ParseFieldNames(fieldsStr string) (map[string]int, error) {
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
