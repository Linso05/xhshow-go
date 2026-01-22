package xhshow

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"strconv"
	"strings"
	"time"
)

const B1SecretKey = "xhswebmplfbt"

type FingerprintGenerator struct {
	b1Key []byte
}

func NewFingerprintGenerator() *FingerprintGenerator {
	return &FingerprintGenerator{
		b1Key: []byte(B1SecretKey),
	}
}

// customQuote 实现 urllib.parse.quote(s, safe="!*'()~_-")
func customQuote(s string) string {
	safeChars := "!*'()~_-"
	var buf bytes.Buffer
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '.' {
			buf.WriteByte(b)
		} else if strings.IndexByte(safeChars, b) != -1 {
			buf.WriteByte(b)
		} else {
			buf.WriteString(fmt.Sprintf("%%%02X", b))
		}
	}
	return buf.String()
}

func (fg *FingerprintGenerator) GenerateB1(fp map[string]interface{}) (string, error) {
	// 提取 B1 所需的特定字段
	keys := []string{
		"x33", "x34", "x35", "x36", "x37", "x38", "x39",
		"x42", "x43", "x44", "x45", "x46", "x48", "x49",
		"x50", "x51", "x52", "x82",
	}
	b1Fp := make(map[string]interface{})
	for _, k := range keys {
		if v, ok := fp[k]; ok {
			b1Fp[k] = v
		}
	}

	// JSON 序列化
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(b1Fp); err != nil {
		return "", err
	}
	// 移除末尾换行符
	jsonBytes := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))

	// RC4 加密
	c, err := rc4.NewCipher(fg.b1Key)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, len(jsonBytes))
	c.XORKeyStream(ciphertext, jsonBytes)

	// Quote (将字节视为 latin1 字符)
	// 在 Go 中，将字节转换为字符串会保留 ASCII 的字节值
	// 对于 > 127 的字节，可能会形成 UTF-8。
	// 我们希望在 customQuote 中逐字节处理。
	// 由于 customQuote 通过字节 (s[i]) 迭代，它将字符串视为字节数组。
	// 因此 `string(ciphertext)` 转换实际上是传递字节切片包装器。
	encodedUrl := customQuote(string(ciphertext))

	// 重建循环 (Python 逻辑的拆分还原)
	// Python 代码:
	// b = []
	// for c in encoded_url.split("%")[1:]:
	//     chars = list(c)
	//     b.append(int("".join(chars[:2]), 16))
	//     [b.append(ord(j)) for j in chars[2:]]

	parts := strings.Split(encodedUrl, "%")
	var b []byte

	// 跳过第一部分 (索引 0)
	for i := 1; i < len(parts); i++ {
		part := parts[i]
		if len(part) < 2 {
			continue
		}

		// 解析前两个字符为十六进制
		hexStr := part[:2]
		val, err := strconv.ParseUint(hexStr, 16, 8)
		if err == nil {
			b = append(b, byte(val))
		}

		// 追加剩余部分作为字节
		for j := 2; j < len(part); j++ {
			b = append(b, part[j])
		}
	}

	return EncodeCustomBase64(b), nil
}

func (fg *FingerprintGenerator) Generate(cookies map[string]interface{}, userAgent string) map[string]interface{} {
	// 构建 Cookie 字符串
	var cookieParts []string
	for k, v := range cookies {
		cookieParts = append(cookieParts, fmt.Sprintf("%s=%v", k, v))
	}
	cookieString := strings.Join(cookieParts, "; ")

	screen := GetScreenConfig()

	// 加权随机选择是否无痕模式
	isIncognito := WeightedRandomChoice([]string{"true", "false"}, []float64{0.95, 0.05})

	vendor, renderer := GetRendererInfo()

	x78_y := mrand.Intn(101) + 2350 // 2350 到 2450

	// 生成 x53 (32 字节随机数的 MD5)
	token := make([]byte, 32)
	rand.Read(token)
	x53Hash := md5.Sum(token)
	x53 := hex.EncodeToString(x53Hash[:])

	// x36 随机整数 1-20
	x36 := strconv.Itoa(mrand.Intn(20) + 1)

	// x44 时间戳
	x44 := strconv.FormatInt(time.Now().UnixMilli(), 10)

	fp := map[string]interface{}{
		"x1":  userAgent,
		"x2":  "false",
		"x3":  "zh-CN",
		"x4":  WeightedRandomChoice(ColorDepthOptions.Values, ColorDepthOptions.Weights),
		"x5":  WeightedRandomChoice(DeviceMemoryOptions.Values, DeviceMemoryOptions.Weights),
		"x6":  "24",
		"x7":  fmt.Sprintf("%s,%s", vendor, renderer),
		"x8":  WeightedRandomChoice(CoreOptions.Values, CoreOptions.Weights),
		"x9":  fmt.Sprintf("%d;%d", screen.Width, screen.Height),
		"x10": fmt.Sprintf("%d;%d", screen.AvailWidth, screen.AvailHeight),
		"x11": "-480",
		"x12": "Asia/Shanghai",
		"x13": isIncognito,
		"x14": isIncognito,
		"x15": isIncognito,
		"x16": "false",
		"x17": "false",
		"x18": "un",
		"x19": "Win32",
		"x20": "",
		"x21": BrowserPlugins,
		"x22": GenerateWebglHash(),
		"x23": "false",
		"x24": "false",
		"x25": "false",
		"x26": "false",
		"x27": "false",
		"x28": "0,false,false",
		"x29": "4,7,8",
		"x30": "swf object not loaded",
		"x33": "0",
		"x34": "0",
		"x35": "0",
		"x36": x36,
		"x37": "0|0|0|0|0|0|0|0|0|1|0|0|0|0|0|0|0|0|1|0|0|0|0|0",
		"x38": "0|0|1|0|1|0|0|0|0|0|1|0|1|0|1|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0",
		"x39": 0,
		"x40": "0",
		"x41": "0",
		"x42": "3.4.4",
		"x43": GenerateCanvasHash(),
		"x44": x44,
		"x45": "__SEC_CAV__1-1-1-1-1|__SEC_WSA__|",
		"x46": "false",
		"x47": "1|0|0|0|0|0",
		"x48": "",
		"x49": "{list:[],type:}",
		"x50": "",
		"x51": "",
		"x52": "",
		"x55": "380,380,360,400,380,400,420,380,400,400,360,360,440,420",
		"x56": fmt.Sprintf("%s|%s|%s|35", vendor, renderer, GenerateWebglHash()),
		"x57": cookieString,
		"x58": "180",
		"x59": "2",
		"x60": "63",
		"x61": "1291",
		"x62": "2047",
		"x63": "0",
		"x64": "0",
		"x65": "0",
		"x66": map[string]interface{}{
			"referer":  "",
			"location": "https://www.xiaohongshu.com/explore",
			"frame":    0,
		},
		"x67": "1|0",
		"x68": "0",
		"x69": "326|1292|30",
		"x70": []string{"location"},
		"x71": "true",
		"x72": "complete",
		"x73": "1191",
		"x74": "0|0|0",
		"x75": "Google Inc.",
		"x76": "true",
		"x77": "1|1|1|1|1|1|1|1|1|1",
		"x78": map[string]interface{}{
			"x":      0,
			"y":      x78_y,
			"left":   0,
			"right":  290.828125,
			"bottom": x78_y + 18,
			"height": 18,
			"top":    x78_y,
			"width":  290.828125,
			"font":   Fonts,
		},
		"x82": "_0x17a2|_0x1954",
		"x31": "124.04347527516074",
		"x79": "144|599565058866",
		"x53": x53,
		"x54": VoiceHashOptions,
		"x80": "1|[object FileSystemDirectoryHandle]",
	}

	return fp
}
