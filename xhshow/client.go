package xhshow

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Client struct {
	xsCommonSigner *XsCommonSigner
}

func NewClient() *Client {
	return &Client{
		xsCommonSigner: NewXsCommonSigner(),
	}
}

// GetXT 返回 x-t 头部值（毫秒级 Unix 时间戳）
func (c *Client) GetXT(timestamp *float64) int64 {
	if timestamp == nil {
		now := float64(time.Now().UnixNano()) / 1e9
		timestamp = &now
	}
	return int64(*timestamp * 1000)
}

// GetB3TraceId 返回 x-b3-traceid
func (c *Client) GetB3TraceId() string {
	return GenerateB3TraceId()
}

// GetXrayTraceId 返回 x-xray-traceid
func (c *Client) GetXrayTraceId(timestamp *int64, seq *int) string {
	var ts int64
	if timestamp != nil {
		ts = *timestamp
	}
	var s int = -1
	if seq != nil {
		s = *seq
	}
	return GenerateXrayTraceId(ts, s)
}

// SignXSCommon 生成 x-s-common 签名
func (c *Client) SignXSCommon(cookies map[string]interface{}) (string, error) {
	return c.xsCommonSigner.Sign(cookies)
}

// SignXS 生成请求签名 (x-s)
func (c *Client) SignXS(method, uri, a1Value, xsecAppId string, payload map[string]interface{}, timestamp *float64) (string, error) {
	if xsecAppId == "" {
		xsecAppId = "xhs-pc-web"
	}

	cleanUri, err := ExtractUri(uri)
	if err != nil {
		return "", err
	}

	contentString, err := c.buildContentString(method, cleanUri, payload)
	if err != nil {
		return "", err
	}

	dValue := c.generateDValue(contentString)

	var ts float64
	if timestamp != nil {
		ts = *timestamp
	} else {
		ts = float64(time.Now().UnixNano()) / 1e9
	}

	sig, err := c.buildSignature(dValue, a1Value, xsecAppId, contentString, ts)
	if err != nil {
		return "", err
	}

	sigData := NewSignatureData()
	sigData.X3 = X3Prefix + sig

	// 使用自定义编码以确保 HTML 字符不被转义，与 Python 行为保持一致
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(sigData); err != nil {
		return "", err
	}
	jsonBytes := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))

	finalSig := XysPrefix + EncodeCustomBase64(jsonBytes)
	return finalSig, nil
}

func (c *Client) buildContentString(method, uri string, payload map[string]interface{}) (string, error) {
	method = strings.ToUpper(method)
	if payload == nil {
		payload = make(map[string]interface{})
	}

	if method == "POST" {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(payload); err != nil {
			return "", err
		}
		jsonBytes := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
		return uri + string(jsonBytes), nil
	} else {
		if len(payload) == 0 {
			return uri, nil
		}
		// 对键进行排序以确保确定性顺序
		keys := make([]string, 0, len(payload))
		for k := range payload {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var params []string
		for _, k := range keys {
			val := payload[k]
			valStr := fmt.Sprintf("%v", val)
			// 处理列表
			if vList, ok := val.([]interface{}); ok {
				// 用逗号连接
				var sList []string
				for _, v := range vList {
					sList = append(sList, fmt.Sprintf("%v", v))
				}
				valStr = strings.Join(sList, ",")
			}

			// 引用字符串，保留 ","
			encodedVal := pythonQuote(valStr)
			params = append(params, fmt.Sprintf("%s=%s", k, encodedVal))
		}
		return fmt.Sprintf("%s?%s", uri, strings.Join(params, "&")), nil
	}
}

func (c *Client) generateDValue(content string) string {
	hash := md5.Sum([]byte(content))
	return hex.EncodeToString(hash[:])
}

func (c *Client) buildSignature(dValue, a1Value, xsecAppId, stringParam string, timestamp float64) (string, error) {
	payloadArray, err := BuildPayloadArray(dValue, a1Value, xsecAppId, stringParam, timestamp)
	if err != nil {
		return "", err
	}

	xorResult, err := XorTransformArray(payloadArray)
	if err != nil {
		return "", err
	}

	// 截断至 124 字节
	if len(xorResult) > 124 {
		xorResult = xorResult[:124]
	}

	return EncodeX3Base64(xorResult), nil
}

// Helpers (辅助函数)

func ExtractUri(u string) (string, error) {
	u = strings.TrimSpace(u)
	parsed, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	if parsed.Path == "" || parsed.Path == "/" {
		// 尝试处理 url.Parse 在缺少协议但以 / 开头时可能无法正确解析路径的情况
		if strings.HasPrefix(u, "/") {
			// 如果存在查询参数则移除
			if idx := strings.Index(u, "?"); idx != -1 {
				return u[:idx], nil
			}
			return u, nil
		}
		// 如果仅为域名 "http://..."，url.Parse 会将路径置为 ""
		return "", fmt.Errorf("cannot extract valid URI path from URL: %s", u)
	}
	return parsed.Path, nil
}

func pythonQuote(s string) string {
	// 模拟 python 的 quote(s, safe=",")
	// Go 的 QueryEscape 会转义所有内容。
	// 空格 -> + (Python 为 %20)
	// , -> %2C (Python 保留 ,)
	res := url.QueryEscape(s)
	res = strings.ReplaceAll(res, "+", "%20")
	res = strings.ReplaceAll(res, "%2C", ",")
	return res
}

// DecodeXS 解密完整的 XYS 签名
func (c *Client) DecodeXS(xsSignature string) (*SignatureData, error) {
	if strings.HasPrefix(xsSignature, XysPrefix) {
		xsSignature = xsSignature[len(XysPrefix):]
	}

	jsonBytes, err := DecodeCustomBase64(xsSignature)
	if err != nil {
		return nil, err
	}

	var sigData SignatureData
	if err := json.Unmarshal(jsonBytes, &sigData); err != nil {
		return nil, err
	}

	return &sigData, nil
}

// DecodeX3 解密 x3 签名
func (c *Client) DecodeX3(x3Signature string) ([]byte, error) {
	if strings.HasPrefix(x3Signature, X3Prefix) {
		x3Signature = x3Signature[len(X3Prefix):]
	}

	decodedBytes, err := DecodeX3Base64(x3Signature)
	if err != nil {
		return nil, err
	}

	// XOR 变换需要 []int
	intArr := make([]int, len(decodedBytes))
	for i, b := range decodedBytes {
		intArr[i] = int(b)
	}

	xorResult, err := XorTransformArray(intArr)
	if err != nil {
		return nil, err
	}

	return xorResult, nil
}
