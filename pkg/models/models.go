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
	SportFilters  []string
	DportFilters  []string

	SIPReverse    bool
	DIPReverse    bool
	DomainReverse bool
	SportReverse  bool
	DportReverse  bool

	SIPFilterMode    int
	DIPFilterMode    int
	DomainFilterMode int
	SportFilterMode  int
	DportFilterMode  int
}

// HasFilters 检查是否有过滤条件
func (f *LogFilters) HasFilters() bool {
	return len(f.SIPFilters) > 0 || len(f.DIPFilters) > 0 || len(f.DomainFilters) > 0 ||
		len(f.SportFilters) > 0 || len(f.DportFilters) > 0 ||
		f.SIPFilterMode != 0 || f.DIPFilterMode != 0 || f.DomainFilterMode != 0 ||
		f.SportFilterMode != 0 || f.DportFilterMode != 0
}
