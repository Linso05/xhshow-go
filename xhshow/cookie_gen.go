package xhshow

import (
	"fmt"
	"hash/crc32"
	"math/rand"
	"time"
)

const Charset = "abcdefghijklmnopqrstuvwxyz1234567890"

// GenerateRandomString generates a random string of given length from Charset
func GenerateRandomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = Charset[rand.Intn(len(Charset))]
	}
	return string(b)
}

// RegisterId generates a random 32-character hex string (webId)
func RegisterId() string {
	s := "abcdef0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = s[rand.Intn(len(s))]
	}
	return string(b)
}

// GenerateA1 generates the 'a1' cookie value
func GenerateA1() string {
	a := 5
	// (+new Date()).toString(16) -> hex string of timestamp in ms
	ts := time.Now().UnixNano() / 1e6
	o := fmt.Sprintf("%x", ts)

	n := o + GenerateRandomString(30)
	r := n + fmt.Sprintf("%d", a)
	e := r + "0"
	u := e + "000"

	// CRC32
	s := crc32.ChecksumIEEE([]byte(u))

	result := (u + fmt.Sprintf("%d", s))
	if len(result) > 52 {
		result = result[:52]
	}
	return result
}

// GetLoadTs returns current timestamp in ms as string
func GetLoadTs() string {
	return fmt.Sprintf("%d", time.Now().UnixNano()/1e6)
}
