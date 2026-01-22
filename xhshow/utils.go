package xhshow

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// --- 位运算 ---

// XorTransformArray 对整数数组执行 XOR 变换
func XorTransformArray(sourceIntegers []int) ([]byte, error) {
	resultBytes := make([]byte, len(sourceIntegers))
	keyBytes, err := hex.DecodeString(HexKey)
	if err != nil {
		return nil, err
	}
	keyLength := len(keyBytes)

	for index, val := range sourceIntegers {
		if index < keyLength {
			resultBytes[index] = byte((val ^ int(keyBytes[index])) & 0xFF)
		} else {
			resultBytes[index] = byte(val & 0xFF)
		}
	}
	return resultBytes, nil
}

func IntToLeBytes(val int, length int) []int {
	arr := make([]int, length)
	for i := 0; i < length; i++ {
		arr[i] = val & 0xFF
		val >>= 8
	}
	return arr
}

// --- 编码 ---

func EncodeCustomBase64(data []byte) string {
	enc := base64.NewEncoding(CustomBase64Alphabet).WithPadding(base64.StdPadding)
	return enc.EncodeToString(data)
}

func EncodeX3Base64(data []byte) string {
	enc := base64.NewEncoding(X3Base64Alphabet).WithPadding(base64.StdPadding)
	return enc.EncodeToString(data)
}

// DecodeCustomBase64 使用 CustomBase64Alphabet 解码
func DecodeCustomBase64(data string) ([]byte, error) {
	enc := base64.NewEncoding(CustomBase64Alphabet).WithPadding(base64.StdPadding)
	return enc.DecodeString(data)
}

// DecodeX3Base64 使用 X3Base64Alphabet 解码
func DecodeX3Base64(data string) ([]byte, error) {
	enc := base64.NewEncoding(X3Base64Alphabet).WithPadding(base64.StdPadding)
	return enc.DecodeString(data)
}

// --- 随机数生成 ---

func GenerateRandomInt() int {
	return rand.Intn(Max32Bit)
}

func GenerateRandomByteInRange(minVal, maxVal int) int {
	return rand.Intn(maxVal-minVal+1) + minVal
}

func GenerateB3TraceId() string {
	b := make([]byte, B3TraceIdLength)
	for i := range b {
		b[i] = HexChars[rand.Intn(len(HexChars))]
	}
	return string(b)
}

func GenerateXrayTraceId(timestamp int64, seq int) string {
	if timestamp == 0 {
		timestamp = time.Now().UnixMilli()
	}
	if seq == -1 {
		seq = rand.Intn(XrayTraceIdSeqMax + 1)
	}

	part1Val := (uint64(timestamp) << XrayTraceIdTimestampShift) | uint64(seq)
	part1 := fmt.Sprintf("%016x", part1Val)

	b := make([]byte, XrayTraceIdPart2Length)
	for i := range b {
		b[i] = HexChars[rand.Intn(len(HexChars))]
	}
	part2 := string(b)

	return part1 + part2
}
