#!/bin/bash

# 使用示例脚本

echo "========== access_log_analyzer 使用示例 =========="
echo ""

# 示例1: 默认用法 (按目的IP+域名统计,显示Top 10)
echo "示例1: 默认用法 - 按目的IP+域名统计,显示Top 10"
echo "./build/access_log_analyzer /path/to/logs"
echo ""

# 示例2: 按源IP+目的IP+域名统计
echo "示例2: 按源IP+目的IP+域名统计,显示Top 20"
echo "./build/access_log_analyzer -fields \"sip,dip,domain\" -top 20 /path/to/logs"
echo ""

# 示例3: 只按域名统计
echo "示例3: 只按域名统计,显示Top 50"
echo "./build/access_log_analyzer -fields \"domain\" -top 50 /path/to/logs"
echo ""

# 示例4: 按目的IP+目的端口+域名统计,指定输出文件名
echo "示例4: 按目的IP+目的端口+域名统计,指定输出文件名"
echo "./build/access_log_analyzer -fields \"dip,dport,domain\" -top 15 -output result.csv /path/to/logs"
echo ""

# 示例5: 按协议类型+域名统计
echo "示例5: 按协议类型+域名统计"
echo "./build/access_log_analyzer -fields \"proto,domain\" -top 30 /path/to/logs"
echo ""

# 示例6: 按源IP+目的IP统计(不区分域名)
echo "示例6: 按源IP+目的IP统计(不区分域名)"
echo "./build/access_log_analyzer -fields \"sip,dip\" -top 25 /path/to/logs"
echo ""

# 示例7: 使用log_path参数
echo "示例7: 使用log_path参数指定日志路径"
echo "./build/access_log_analyzer -log_path /path/to/logs -top 20"
echo ""

# 示例8: 按源IP过滤
echo "示例8: 只统计源IP为192.168.1.100的流量"
echo "./build/access_log_analyzer -sip 192.168.1.100 /path/to/logs"
echo ""

# 示例9: 按目的IP过滤,支持模糊匹配
echo "示例9: 统计目的IP为10.0.0.*的流量(模糊匹配)"
echo "./build/access_log_analyzer -dip \"10.0.0.*\" /path/to/logs"
echo ""

# 示例10: 多个过滤条件组合
echo "示例10: 组合多个过滤条件"
echo "./build/access_log_analyzer -sip 192.168.1.* -dip 10.0.0.1,10.0.0.2 /path/to/logs"
echo ""

# 示例11: 域名过滤,支持多个值和模糊匹配
echo "示例11: 域名过滤,支持多个值和模糊匹配"
echo "./build/access_log_analyzer -domain \"*.example.com,test.com\" /path/to/logs"
echo ""

# 示例12: 按上行流量排序(默认)
echo "示例12: 按上行流量排序(默认)"
echo "./build/access_log_analyzer -sort up /path/to/logs"
echo ""

# 示例13: 按下行流量排序
echo "示例13: 按下行流量排序"
echo "./build/access_log_analyzer -sort down /path/to/logs"
echo ""

# 示例14: 按总流量排序
echo "示例14: 按总流量排序"
echo "./build/access_log_analyzer -sort total /path/to/logs"
echo ""

echo "========== 支持的字段列表 =========="
echo "house_id     - HouseId"
echo "sip          - 源IP"
echo "dip          - 目的IP"
echo "proto        - 协议类型"
echo "sport        - 源端口"
echo "dport        - 目的端口"
echo "domain       - 域名"
echo "url          - URL"
echo "duration     - Duration"
echo "utc_time     - UTC时间"
echo "title        - Title"
echo "app_proto    - 应用层协议"
echo "biz_proto    - 业务层协议"
echo "referer      - Referer"
echo "location     - Location"
echo "content      - 网站内容"
echo "data_size    - 访问数据量"
echo "up_traffic   - 上行流量"
echo "down_traffic - 下行流量"
echo "app_name     - 应用名称"
echo ""

echo "========== 参数说明 =========="
echo "-fields    统计字段,用逗号分隔 (默认: dip,domain)"
echo "-top       显示Top N条记录 (默认: 10)"
echo "-sort      排序方式: up(上行流量), down(下行流量), total(总流量) (默认: up)"
echo "-output    输出CSV文件名 (默认: 自动生成 traffic_stats_时间戳.csv)"
echo "-log_path  日志文件路径(目录或tar.gz文件)"
echo "-sip       源IP过滤,支持逗号分隔多个值,支持*模糊匹配"
echo "-dip       目的IP过滤,支持逗号分隔多个值,支持*模糊匹配"
echo "-domain    域名过滤,支持逗号分隔多个值,支持*模糊匹配"
echo ""
echo "========== 过滤示例 =========="
echo "完全匹配: -sip 192.168.1.100"
echo "模糊匹配: -dip \"10.0.0.*\""
echo "多个值:   -domain \"*.example.com,test.com\""
echo "组合过滤: -sip 192.168.* -dip 10.0.0.1 -domain \"*.quark.cn\""
echo ""
