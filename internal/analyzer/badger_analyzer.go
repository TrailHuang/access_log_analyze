package analyzer

import (
	"access_log_analyze/pkg/models"
	"access_log_analyze/pkg/storage"
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcessTarGzWithBadger 处理单个tar.gz文件，聚合到 localMap
func ProcessTarGzWithBadger(filePath string, fieldIndexes map[string]int, filters *models.LogFilters, localMap map[string]*storage.TrafficRecord) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("创建gzip reader失败: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取tar文件失败: %w", err)
		}

		if header.Typeflag == tar.TypeReg && strings.HasSuffix(strings.ToLower(header.Name), ".txt") {
			err = processLogWithBadger(tarReader, fieldIndexes, filters, localMap)
			if err != nil {
				return fmt.Errorf("处理日志文件 %s 失败: %w", header.Name, err)
			}
		}
	}

	return nil
}

func processLogWithBadger(reader io.Reader, fieldIndexes map[string]int, filters *models.LogFilters, localMap map[string]*storage.TrafficRecord) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

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

	type filterField struct {
		name    string
		idx     int
		enabled bool
	}
	filterFields := []filterField{
		{"sip", 1, len(filters.SIPFilters) > 0},
		{"dip", 2, len(filters.DIPFilters) > 0},
		{"domain", 6, len(filters.DomainFilters) > 0},
		{"sport", 4, len(filters.SportFilters) > 0},
		{"dport", 5, len(filters.DportFilters) > 0},
		{"url", 7, len(filters.URLFilters) > 0},
	}

	fieldIndexSet := make(map[string]bool, len(sortedFields))
	for _, fp := range sortedFields {
		fieldIndexSet[fp.name] = true
	}
	for i := range filterFields {
		if fieldIndexSet[filterFields[i].name] {
			filterFields[i].enabled = false
		}
	}

	needFilter := len(filters.SIPFilters) > 0 || len(filters.DIPFilters) > 0 || len(filters.DomainFilters) > 0 ||
		len(filters.SportFilters) > 0 || len(filters.DportFilters) > 0 || len(filters.URLFilters) > 0 ||
		filters.SIPFilterMode != 0 || filters.DIPFilterMode != 0 || filters.DomainFilterMode != 0 ||
		filters.SportFilterMode != 0 || filters.DportFilterMode != 0 || filters.URLFilterMode != 0

	positions := make([]fieldPos, 0, 32)
	fieldValueSlice := make([]string, len(sortedFields))

	for scanner.Scan() {
		lineBytes := scanner.Bytes()

		if len(lineBytes) == 0 {
			continue
		}
		allSpace := true
		for _, b := range lineBytes {
			if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
				allSpace = false
				break
			}
		}
		if allSpace {
			continue
		}

		positions = findFieldPositions(lineBytes, positions[:0])

		if len(positions) < 20 {
			continue
		}

		if needFilter {
			skip := false
			for _, ff := range filterFields {
				var value string
				if ff.enabled {
					value = getFieldString(lineBytes, positions, ff.idx)
				} else {
					for _, fp := range sortedFields {
						if fp.name == ff.name {
							value = getFieldString(lineBytes, positions, fp.idx)
							break
						}
					}
				}

				switch ff.name {
				case "sip":
					if !MatchFilter(value, filters.SIPFilters, filters.SIPReverse) {
						skip = true
					}
				case "dip":
					if !MatchFilter(value, filters.DIPFilters, filters.DIPReverse) {
						skip = true
					}
				case "domain":
					if !MatchFilter(value, filters.DomainFilters, filters.DomainReverse) {
						skip = true
					}
				case "sport":
					if !MatchFilter(value, filters.SportFilters, filters.SportReverse) {
						skip = true
					}
				case "dport":
					if !MatchFilter(value, filters.DportFilters, filters.DportReverse) {
						skip = true
					}
				case "url":
					if !MatchURLFilter(value, filters) {
						skip = true
					}
				}

				if skip {
					break
				}
			}
			if skip {
				continue
			}
		}

		if filters.SIPFilterMode != 0 || filters.DIPFilterMode != 0 || filters.DomainFilterMode != 0 || filters.SportFilterMode != 0 || filters.DportFilterMode != 0 || filters.URLFilterMode != 0 {
			skip := false

			if filters.SIPFilterMode != 0 {
				value := getFieldString(lineBytes, positions, 1)
				isEmpty := value == "" || value == "-"
				if (filters.SIPFilterMode == 1 && !isEmpty) || (filters.SIPFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && filters.DIPFilterMode != 0 {
				value := getFieldString(lineBytes, positions, 2)
				isEmpty := value == "" || value == "-"
				if (filters.DIPFilterMode == 1 && !isEmpty) || (filters.DIPFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && filters.DomainFilterMode != 0 {
				value := getFieldString(lineBytes, positions, 6)
				isEmpty := value == "" || value == "-"
				if (filters.DomainFilterMode == 1 && !isEmpty) || (filters.DomainFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && filters.SportFilterMode != 0 {
				value := getFieldString(lineBytes, positions, 4)
				isEmpty := value == "" || value == "-"
				if (filters.SportFilterMode == 1 && !isEmpty) || (filters.SportFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && filters.DportFilterMode != 0 {
				value := getFieldString(lineBytes, positions, 5)
				isEmpty := value == "" || value == "-"
				if (filters.DportFilterMode == 1 && !isEmpty) || (filters.DportFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if !skip && filters.URLFilterMode != 0 {
				value := getFieldString(lineBytes, positions, 7)
				isEmpty := value == "" || value == "-"
				if (filters.URLFilterMode == 1 && !isEmpty) || (filters.URLFilterMode == 2 && isEmpty) {
					skip = true
				}
			}

			if skip {
				continue
			}
		}

		keyBuilder := KeyBuilderPool.Get().(*strings.Builder)
		keyBuilder.Reset()

		for i, fp := range sortedFields {
			value := getFieldString(lineBytes, positions, fp.idx)
			if value == "" {
				value = "-"
			}
			fieldValueSlice[i] = value
			if i > 0 {
				keyBuilder.WriteByte('|')
			}
			keyBuilder.WriteString(value)
		}

		key := strings.Clone(keyBuilder.String())
		KeyBuilderPool.Put(keyBuilder)

		if key == "" {
			continue
		}

		upTrafficStr := getFieldString(lineBytes, positions, 18)
		downTrafficStr := getFieldString(lineBytes, positions, 19)
		upTraffic, _ := strconv.ParseInt(upTrafficStr, 10, 64)
		downTraffic, _ := strconv.ParseInt(downTrafficStr, 10, 64)

		if existing, ok := localMap[key]; ok {
			existing.UpTotal += upTraffic
			existing.DownTotal += downTraffic
			existing.FlowTotal++
		} else {
			fieldValues := make(map[string]string, len(sortedFields)+3)
			for i, fp := range sortedFields {
				fieldValues[fp.name] = fieldValueSlice[i]
			}
			for _, ff := range filterFields {
				if ff.enabled {
					value := getFieldString(lineBytes, positions, ff.idx)
					if value == "" {
						value = "-"
					}
					fieldValues[ff.name] = value
				}
			}
			localMap[key] = &storage.TrafficRecord{
				Key:       key,
				Fields:    fieldValues,
				UpTotal:   upTraffic,
				DownTotal: downTraffic,
				FlowTotal: 1,
			}
		}
	}

	return scanner.Err()
}

// flushLocalMap 将本地 map 刷入 BadgerDB 并重置 map
func flushLocalMap(db *storage.BadgerStorage, localMap *map[string]*storage.TrafficRecord) error {
	if len(*localMap) == 0 {
		return nil
	}
	records := make([]*storage.TrafficRecord, 0, len(*localMap))
	for _, r := range *localMap {
		records = append(records, r)
	}
	if err := db.BatchUpsert(records); err != nil {
		return err
	}
	*localMap = make(map[string]*storage.TrafficRecord, 50000)
	return nil
}

// ProcessFilesWithBadger 使用BadgerDB并发处理文件
// 每个 worker 维护本地 map 跨文件累积，达到阈值才 flush 到 BadgerDB
func ProcessFilesWithBadger(files []string, fieldIndexes map[string]int, filters *models.LogFilters, numWorkers int, flushThreshold int) (*storage.BadgerStorage, error) {
	if numWorkers > len(files) {
		numWorkers = len(files)
	}
	if numWorkers == 0 {
		return nil, fmt.Errorf("没有文件需要处理")
	}
	if flushThreshold <= 0 {
		flushThreshold = 500000
	}

	db, err := storage.CreateTempDB("access_log_")
	if err != nil {
		return nil, fmt.Errorf("创建BadgerDB失败: %w", err)
	}

	fmt.Printf("使用 %d 个协程并发处理 (BadgerDB存储, 内存阈值%d条)\n", numWorkers, flushThreshold)

	taskCh := make(chan string, len(files))
	for _, file := range files {
		taskCh <- file
	}
	close(taskCh)

	type fileResult struct {
		err error
	}
	resultCh := make(chan fileResult, len(files))

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			localMap := make(map[string]*storage.TrafficRecord, 50000)

			for filePath := range taskCh {
				fileStart := time.Now()
				fileName := filepath.Base(filePath)

				err := ProcessTarGzWithBadger(filePath, fieldIndexes, filters, localMap)
				fileDuration := time.Since(fileStart)

				if err != nil {
					fmt.Printf("  [Worker %d] 警告: 处理文件 %s 时出错: %v (%.2fs)\n", workerID, fileName, err, fileDuration.Seconds())
					resultCh <- fileResult{err: err}
				} else {
					fmt.Printf("  [Worker %d] ✓ %s 处理完成 (%.2fs)\n", workerID, fileName, fileDuration.Seconds())
					resultCh <- fileResult{}
				}

				// 本地 map 超过阈值时 flush 到 BadgerDB，释放内存
				if len(localMap) >= flushThreshold {
					if flushErr := flushLocalMap(db, &localMap); flushErr != nil {
						fmt.Printf("  [Worker %d] 警告: flush到BadgerDB失败: %v\n", workerID, flushErr)
					}
				}
			}

			// flush 剩余数据
			if len(localMap) > 0 {
				if flushErr := flushLocalMap(db, &localMap); flushErr != nil {
					fmt.Printf("  [Worker %d] 警告: 最终flush失败: %v\n", workerID, flushErr)
				}
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	processedFiles := 0
	failedFiles := 0
	for res := range resultCh {
		processedFiles++
		if res.err != nil {
			failedFiles++
		}
	}

	fmt.Printf("\n处理完成: 成功 %d 个, 失败 %d 个\n", processedFiles-failedFiles, failedFiles)

	if count, err := db.GetRecordCount(); err == nil {
		fmt.Printf("总记录数: %d\n", count)
	}

	return db, nil
}
