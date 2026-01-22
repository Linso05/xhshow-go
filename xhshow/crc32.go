package xhshow

import "hash/crc32"

// CRC32_JS_Int 实现自定义 CRC32 逻辑
// 公式: (-1 ^ c ^ 0xEDB88320) >>> 0
// 其中 c 是标准 CRC32 (IEEE) 结果
func CRC32_JS_Int(data []byte) int32 {
	c := crc32.ChecksumIEEE(data)
	poly := uint32(0xEDB88320)
	// Python 实现: ((MASK32 ^ c) ^ POLY) & MASK32
	// MASK32 ^ c 是 c 的按位取反 (Go 中 uint32 的 ^c)
	u := ^c ^ poly
	return int32(u)
}
