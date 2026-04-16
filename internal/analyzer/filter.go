package analyzer

import (
	"regexp"
	"strings"
)

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

// ParseFilterPatterns 解析过滤模式
func ParseFilterPatterns(filterStr string) []string {
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
