package xhshow

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const PublicUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"

type XsCommonSigner struct {
	fpGenerator *FingerprintGenerator
}

func NewXsCommonSigner() *XsCommonSigner {
	return &XsCommonSigner{
		fpGenerator: NewFingerprintGenerator(),
	}
}

// Sign 生成 x-s-common 签名
func (s *XsCommonSigner) Sign(cookieDict map[string]interface{}) (string, error) {
	// 1. 生成指纹
	fp := s.fpGenerator.Generate(cookieDict, PublicUserAgent)

	// 2. 生成 b1
	b1, err := s.fpGenerator.GenerateB1(fp)
	// fmt.Printf("b1: %s\n", b1)
	if err != nil {
		return "", err
	}

	// 3. 计算 b1 的 CRC32
	x9 := CRC32_JS_Int([]byte(b1))

	// 4. 构建签名 Map
	a1Val, ok := cookieDict["a1"]
	if !ok {
		return "", fmt.Errorf("missing 'a1' in cookieDict")
	}
	a1Str := fmt.Sprintf("%v", a1Val)

	sig := map[string]interface{}{
		"s0":  5,
		"s1":  "",
		"x0":  "1",
		"x1":  "4.2.6",
		"x2":  "Windows",
		"x3":  "xhs-pc-web",
		"x4":  "4.86.0",
		"x5":  a1Str,
		"x6":  "",
		"x7":  "",
		"x8":  b1,
		"x9":  x9,
		"x10": 0,
		"x11": "normal",
	}

	// 5. 编码
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(sig); err != nil {
		return "", err
	}
	// 移除末尾换行符
	jsonBytes := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))

	return EncodeCustomBase64(jsonBytes), nil
}
