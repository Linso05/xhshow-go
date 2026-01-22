package xhshow

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// EnvFingerprintA 生成带有校验和的环境指纹 A
func EnvFingerprintA(ts int64, xorKey int) []int {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(ts))

	var sum1 int
	for i := 1; i < 5; i++ {
		sum1 += int(buf[i])
	}
	var sum2 int
	for i := 5; i < 8; i++ {
		sum2 += int(buf[i])
	}

	mark := ((sum1 & 0xFF) + sum2) & 0xFF
	buf[0] = byte(mark)

	res := make([]int, 8)
	for i := 0; i < 8; i++ {
		res[i] = int(buf[i] ^ byte(xorKey))
	}
	return res
}

// EnvFingerprintB 生成简单的环境指纹 B（无加密）
func EnvFingerprintB(ts int64) []int {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(ts))
	res := make([]int, 8)
	for i := 0; i < 8; i++ {
		res[i] = int(buf[i])
	}
	return res
}

// BuildPayloadArray 完全按照 t.js/python 版本构建 payload 数组
func BuildPayloadArray(hexParameter, a1Value, appIdentifier, stringParam string, timestamp float64) ([]int, error) {
	var payload []int

	// 1. 版本字节
	for _, b := range VersionBytes {
		payload = append(payload, int(b))
	}

	// 2. 随机种子
	seed := GenerateRandomInt()
	seedBytes := IntToLeBytes(seed, 4)
	for _, b := range seedBytes {
		payload = append(payload, b)
	}
	seedByte0 := seedBytes[0]

	// 时间戳处理
	if timestamp == 0 {
		timestamp = float64(time.Now().UnixNano()) / 1e9
	}

	// 3. 环境指纹 A
	tsMillis := int64(timestamp * 1000)
	fpA := EnvFingerprintA(tsMillis, EnvFingerprintXorKey)
	payload = append(payload, fpA...)

	// 4. 环境指纹 B (时间偏移)
	timeOffset := GenerateRandomByteInRange(EnvFingerprintTimeOffsetMin, EnvFingerprintTimeOffsetMax)
	tsOffsetMillis := int64((timestamp - float64(timeOffset)) * 1000)
	fpB := EnvFingerprintB(tsOffsetMillis)
	payload = append(payload, fpB...)

	// 5. 序列值
	seqVal := GenerateRandomByteInRange(SequenceValueMin, SequenceValueMax)
	seqBytes := IntToLeBytes(seqVal, 4)
	payload = append(payload, seqBytes...)

	// 6. 窗口属性长度
	winLen := GenerateRandomByteInRange(WindowPropsLengthMin, WindowPropsLengthMax)
	winBytes := IntToLeBytes(winLen, 4)
	payload = append(payload, winBytes...)

	// 7. URI 长度
	uriLen := len(stringParam)
	uriLenBytes := IntToLeBytes(uriLen, 4)
	payload = append(payload, uriLenBytes...)

	// 8. MD5 XOR 段
	md5Bytes, err := hex.DecodeString(hexParameter)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 8; i++ {
		// Python 实现: payload.append(md5_bytes[i] ^ seed_byte_0)
		payload = append(payload, int(md5Bytes[i])^seedByte0)
	}

	// 9. A1 长度
	payload = append(payload, 52)

	// 10. A1 内容
	a1Bytes := []byte(a1Value)
	if len(a1Bytes) > 52 {
		a1Bytes = a1Bytes[:52]
	} else if len(a1Bytes) < 52 {
		// 用 0 填充
		padded := make([]byte, 52)
		copy(padded, a1Bytes)
		a1Bytes = padded
	}
	for _, b := range a1Bytes {
		payload = append(payload, int(b))
	}

	// 11. 来源长度
	payload = append(payload, 10)

	// 12. 来源内容
	srcBytes := []byte(appIdentifier)
	if len(srcBytes) > 10 {
		srcBytes = srcBytes[:10]
	} else if len(srcBytes) < 10 {
		padded := make([]byte, 10)
		copy(padded, srcBytes)
		srcBytes = padded
	}
	for _, b := range srcBytes {
		payload = append(payload, int(b))
	}

	// 13. 固定值 1
	payload = append(payload, 1)

	// 14. 校验和版本
	payload = append(payload, ChecksumVersion)

	// 15. 校验和 XOR
	payload = append(payload, seedByte0^ChecksumXorKey)

	// 16. 校验和固定尾部
	for _, b := range ChecksumFixedTail {
		payload = append(payload, int(b))
	}

	return payload, nil
}

type X3Payload struct {
	Version        []byte
	Seed           int
	TimestampRaw   int64
	Sequence       int
	WindowPropsLen int
	UriLen         int
	Md5Hex         string
	A1             string
	Source         string
}

// ParseX3Payload 解析解密后的 x3 payload
func ParseX3Payload(payload []byte) (*X3Payload, error) {
	if len(payload) < 124 {
		return nil, fmt.Errorf("payload too short: %d < 124", len(payload))
	}

	res := &X3Payload{}

	// 1. 版本 (4 字节)
	res.Version = make([]byte, 4)
	copy(res.Version, payload[:4])

	// 2. 随机种子 (4 字节小端序)
	res.Seed = int(binary.LittleEndian.Uint32(payload[4:8]))
	seedByte0 := payload[4]

	// 4. 环境指纹 B (8 字节) - payload[16:24]
	// 包含 (ts - offset)。
	res.TimestampRaw = int64(binary.LittleEndian.Uint64(payload[16:24]))

	// 5. 序列号 (4 字节) - payload[24:28]
	res.Sequence = int(binary.LittleEndian.Uint32(payload[24:28]))

	// 6. 窗口属性长度 (4 字节) - payload[28:32]
	res.WindowPropsLen = int(binary.LittleEndian.Uint32(payload[28:32]))

	// 7. URI 长度 (4 字节) - payload[32:36]
	res.UriLen = int(binary.LittleEndian.Uint32(payload[32:36]))

	// 8. MD5 XOR 段 (8 字节) - payload[36:44]
	md5Bytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		md5Bytes[i] = payload[36+i] ^ seedByte0
	}
	res.Md5Hex = hex.EncodeToString(md5Bytes)

	// 10. A1 内容 (52 字节) - payload[45:97]
	a1Bytes := payload[45:97]
	a1Bytes = bytes.TrimRight(a1Bytes, "\x00")
	res.A1 = string(a1Bytes)

	// 12. 来源内容 (10 字节) - payload[98:108]
	srcBytes := payload[98:108]
	srcBytes = bytes.TrimRight(srcBytes, "\x00")
	res.Source = string(srcBytes)

	return res, nil
}
