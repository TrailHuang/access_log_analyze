package storage

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dgraph-io/badger/v4"
)

// TrafficRecord 流量统计记录（用于BadgerDB存储）
type TrafficRecord struct {
	Key       string
	Fields    map[string]string
	UpTotal   int64
	DownTotal int64
	FlowTotal int64
}

// BadgerStorage BadgerDB存储引擎
type BadgerStorage struct {
	db     *badger.DB
	dbPath string
}

// NewBadgerStorage 创建BadgerDB存储实例
func NewBadgerStorage(dbPath string) (*BadgerStorage, error) {
	if err := os.MkdirAll(dbPath, 0755); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %w", err)
	}

	opts := badger.DefaultOptions(dbPath).
		WithLoggingLevel(badger.ERROR).
		WithSyncWrites(false).
		WithNumVersionsToKeep(1).
		WithMemTableSize(256 << 20) // 256MB memtable，加速读取

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("打开BadgerDB失败: %w", err)
	}

	return &BadgerStorage{
		db:     db,
		dbPath: dbPath,
	}, nil
}

// Close 关闭数据库
func (s *BadgerStorage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Cleanup 清理数据库文件
func (s *BadgerStorage) Cleanup() error {
	s.Close()
	return os.RemoveAll(s.dbPath)
}

// BatchWrite 纯写入，不做读取合并（数据已在外部聚合完成）
func (s *BadgerStorage) BatchWrite(records map[string]*TrafficRecord) error {
	if len(records) == 0 {
		return nil
	}

	wb := s.db.NewWriteBatch()
	defer wb.Cancel()

	for _, record := range records {
		if record.Key == "" {
			continue
		}
		data, err := serializeRecord(record)
		if err != nil {
			return fmt.Errorf("BatchWrite: serialize failed for key=%q: %w", record.Key, err)
		}
		if err := wb.Set([]byte(record.Key), data); err != nil {
			return fmt.Errorf("BatchWrite: write failed for key=%q: %w", record.Key, err)
		}
	}

	return wb.Flush()
}

// BatchUpsert 批量插入或更新记录（读-合并-写，用于兼容旧接口）
func (s *BadgerStorage) BatchUpsert(records []*TrafficRecord) error {
	if len(records) == 0 {
		return nil
	}

	// 过滤空 key
	validRecords := make([]*TrafficRecord, 0, len(records))
	for _, r := range records {
		if r.Key != "" {
			validRecords = append(validRecords, r)
		}
	}
	if len(validRecords) == 0 {
		return nil
	}

	// 第一步：批量读取已有记录
	type mergedRecord struct {
		record *TrafficRecord
		exists bool
	}
	merged := make([]mergedRecord, len(validRecords))

	err := s.db.View(func(txn *badger.Txn) error {
		for i, record := range validRecords {
			existing, err := s.getRecord(txn, record.Key)
			if err != nil && err != badger.ErrKeyNotFound {
				return fmt.Errorf("BatchUpsert: getRecord failed for key=%q: %w", record.Key, err)
			}
			if err == nil {
				existing.UpTotal += record.UpTotal
				existing.DownTotal += record.DownTotal
				existing.FlowTotal += record.FlowTotal
				merged[i] = mergedRecord{record: existing, exists: true}
			} else {
				merged[i] = mergedRecord{record: record, exists: false}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// 第二步：用 WriteBatch 批量写入
	wb := s.db.NewWriteBatch()
	defer wb.Cancel()

	for _, m := range merged {
		data, err := serializeRecord(m.record)
		if err != nil {
			return fmt.Errorf("BatchUpsert: serialize failed for key=%q: %w", m.record.Key, err)
		}
		if err := wb.Set([]byte(m.record.Key), data); err != nil {
			return fmt.Errorf("BatchUpsert: write failed for key=%q: %w", m.record.Key, err)
		}
	}

	return wb.Flush()
}

// GetAllRecords 获取所有记录
func (s *BadgerStorage) GetAllRecords() ([]*TrafficRecord, error) {
	var records []*TrafficRecord

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			val, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}

			record, err := deserializeRecord(val)
			if err != nil {
				return err
			}
			record.Key = string(item.KeyCopy(nil))
			records = append(records, record)
		}
		return nil
	})

	return records, err
}

// GetRecordCount 获取记录总数
func (s *BadgerStorage) GetRecordCount() (int, error) {
	count := 0
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			count++
		}
		return nil
	})
	return count, err
}

// getRecord 从事务中获取记录
func (s *BadgerStorage) getRecord(txn *badger.Txn, key string) (*TrafficRecord, error) {
	item, err := txn.Get([]byte(key))
	if err != nil {
		return nil, err
	}

	val, err := item.ValueCopy(nil)
	if err != nil {
		return nil, err
	}

	record, err := deserializeRecord(val)
	if err != nil {
		return nil, err
	}
	record.Key = key
	return record, nil
}

// serializeRecord 序列化记录
func serializeRecord(record *TrafficRecord) ([]byte, error) {
	fieldsLen := len(record.Fields)
	size := 8 + 8 + 8 + 4 // UpTotal + DownTotal + FlowTotal + fieldsLen

	for k, v := range record.Fields {
		size += 4 + len(k) + 4 + len(v)
	}

	buf := make([]byte, 0, size)

	buf = appendInt64(buf, record.UpTotal)
	buf = appendInt64(buf, record.DownTotal)
	buf = appendInt64(buf, record.FlowTotal)
	buf = appendInt32(buf, int32(fieldsLen))

	for k, v := range record.Fields {
		buf = appendString(buf, k)
		buf = appendString(buf, v)
	}

	return buf, nil
}

// deserializeRecord 反序列化记录
func deserializeRecord(data []byte) (*TrafficRecord, error) {
	pos := 0

	upTotal := int64(binary.LittleEndian.Uint64(data[pos:]))
	pos += 8

	downTotal := int64(binary.LittleEndian.Uint64(data[pos:]))
	pos += 8

	flowTotal := int64(binary.LittleEndian.Uint64(data[pos:]))
	pos += 8

	fieldsLen := int32(binary.LittleEndian.Uint32(data[pos:]))
	pos += 4

	fields := make(map[string]string, fieldsLen)
	for i := int32(0); i < fieldsLen; i++ {
		key, n := readString(data[pos:])
		pos += n
		value, n := readString(data[pos:])
		pos += n
		fields[key] = value
	}

	return &TrafficRecord{
		UpTotal:   upTotal,
		DownTotal: downTotal,
		FlowTotal: flowTotal,
		Fields:    fields,
	}, nil
}

func appendInt64(buf []byte, v int64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	return append(buf, b...)
}

func appendInt32(buf []byte, v int32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return append(buf, b...)
}

func appendString(buf []byte, s string) []byte {
	buf = appendInt32(buf, int32(len(s)))
	return append(buf, s...)
}

func readString(data []byte) (string, int) {
	length := int32(binary.LittleEndian.Uint32(data))
	pos := 4
	return string(data[pos : pos+int(length)]), pos + int(length)
}

// GetDBPath 获取数据库路径
func (s *BadgerStorage) GetDBPath() string {
	return s.dbPath
}

// CreateTempDB 创建临时数据库
func CreateTempDB(prefix string) (*BadgerStorage, error) {
	tempDir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return nil, fmt.Errorf("创建临时目录失败: %w", err)
	}

	dbPath := filepath.Join(tempDir, "badger")
	return NewBadgerStorage(dbPath)
}
