package models

// ExportRecord 导出的话单记录
type ExportRecord struct {
	HouseID     string // 0: HouseId
	SIP         string // 1: 源IP
	DIP         string // 2: 目的IP
	Proto       string // 3: 协议类型
	Sport       string // 4: 源端口
	Dport       string // 5: 目的端口
	Domain      string // 6: 域名
	URL         string // 7: URL
	Duration    string // 8: Duration
	UTCTime     string // 9: UTC时间
	Title       string // 10: Title
	TrafficType string // 11: 流量类型
	TransProto  string // 12: 传输层协议
	AppProto    string // 13: 应用层协议
	BizProto    string // 14: 业务层协议
	Referer     string // 15: Referer
	Location    string // 16: Location
	SiteContent string // 17: 网站内容
	AccessData  string // 18: 访问数据量
	UpTraffic   string // 19: 上行流量
	DownTraffic string // 20: 下行流量
	AppName     string // 21: 应用名称
}
