package analyzer

import (
	"regexp"
	"strings"
	"sync"
)

// compiledRegexCache 缓存已编译的正则表达式
var compiledRegexCache sync.Map

// MatchFilter 检查值是否匹配过滤条件
// reverse=true时：排除匹配的项（反向过滤）
// reverse=false时：保留匹配的项（正向过滤，默认行为）
func MatchFilter(value string, filters []string, reverse bool) bool {
	if len(filters) == 0 {
		return true // 没有过滤条件,默认匹配
	}

	matched := false
	for _, pattern := range filters {
		if matchPattern(value, pattern) {
			matched = true
			break
		}
	}

	// 反向过滤：匹配到的排除（返回false），未匹配的保留（返回true）
	// 正向过滤：匹配到的保留（返回true），未匹配的排除（返回false）
	if reverse {
		return !matched
	}
	return matched
}

// matchPattern 匹配单个模式,支持*通配符
func matchPattern(value, pattern string) bool {
	// 如果没有*,完全匹配
	if !strings.Contains(pattern, "*") {
		return value == pattern
	}

	// 从缓存获取或编译正则表达式
	re, ok := compiledRegexCache.Load(pattern)
	if !ok {
		regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")
		compiled, err := regexp.Compile(regexPattern)
		if err != nil {
			return false
		}
		re, _ = compiledRegexCache.LoadOrStore(pattern, compiled)
	}

	return re.(*regexp.Regexp).MatchString(value)
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
