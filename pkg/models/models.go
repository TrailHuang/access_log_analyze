package models

// TrafficStats 存储流量统计数据
type TrafficStats struct {
	Key       string            // 统计key (由指定字段组合)
	Fields    map[string]string // 各字段的值
	UpTotal   int64
	DownTotal int64
	FlowTotal int64
}

// CSVRecord 存储CSV中的一条记录
type CSVRecord struct {
	Key       string            // 由fields指定的字段组合作为key
	Fields    map[string]string // 各字段的值
	UpTotal   int64
	DownTotal int64
	FlowTotal int64
	FlowCount int64
}

// LogFilters 日志过滤器
type LogFilters struct {
	SIPFilters    []string
	DIPFilters    []string
	DomainFilters []string
}

// HasFilters 检查是否有过滤条件
func (f *LogFilters) HasFilters() bool {
	return len(f.SIPFilters) > 0 || len(f.DIPFilters) > 0 || len(f.DomainFilters) > 0
}
