# xhshow-go

<div align="center">

小红书请求签名生成库的 Go (Golang) 实现，支持 `GET`/`POST` 请求的 `x-s` 和 `x-s-common` 签名，并提供相关辅助工具。

本项目基于 [Cloxl/xhshow](https://github.com/Cloxl/xhshow) 的 Python 实现移植，感谢原作者的无私奉献！

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

> ⚠️ **声明**：本项目中约 60% 的代码 由 AI 辅助完成，不保证与上游仓库行为完全一致。

## 致谢

特别感谢 [Cloxl](https://github.com/Cloxl) 开源的 [xhshow](https://github.com/Cloxl/xhshow) 项目，本项目的核心算法逻辑均来源于此。



## 快速开始

以下示例展示了如何使用 `xhshow-go` 生成 `x-s` 和 `x-s-common` 签名，以及获取其他必要的请求头。

```go
package main

import (
	"fmt"
	"log"
	"xhshow-go/xhshow"
)

func main() {
	client := xhshow.NewClient()

	// 请替换为您的真实 A1 Cookie 值
	a1Value := "your_a1_cookie_value"
	// 如果需要 x-s-common，请替换为您的 web_session 值
	webSessionValue := "your_web_session_value"

	// --------------------------------------------------
	// 1. 生成 GET 请求所需的所有签名和头部
	// --------------------------------------------------
	fmt.Println("--- GET 请求示例 ---")
	getMethod := "GET"
	getURI := "/api/sns/web/v1/user_posted"
	getQueryParams := map[string]interface{}{
		"num":     30,
		"cursor":  "",
		"user_id": "123",
	}

	// 生成 x-s 签名
	xsGet, err := client.SignXS(getMethod, getURI, a1Value, "xhs-pc-web", getQueryParams, nil)
	if err != nil {
		log.Fatalf("生成 GET x-s 签名失败: %v", err)
	}

	// 生成 x-s-common 签名
	cookiesMap := map[string]interface{}{
		"a1":          a1Value,
		"web_session": webSessionValue,
	}
	xsCommon, err := client.SignXSCommon(cookiesMap)
	if err != nil {
		log.Fatalf("生成 x-s-common 失败: %v", err)
	}

	// 生成其他头部
	xt := client.GetXT(nil)
	b3TraceId := client.GetB3TraceId()
	xrayTraceId := client.GetXrayTraceId(nil, nil)

	fmt.Printf("x-s: %s\n", xsGet)
	fmt.Printf("x-t: %d\n", xt)
	fmt.Printf("x-b3-traceid: %s\n", b3TraceId)
	fmt.Printf("x-xray-traceid: %s\n", xrayTraceId)
	fmt.Printf("x-s-common: %s\n\n", xsCommon)


	// --------------------------------------------------
	// 2. 生成 POST 请求所需的所有签名和头部
	// --------------------------------------------------
	fmt.Println("--- POST 请求示例 ---")
	postMethod := "POST"
	postURI := "/api/sns/web/v1/login"
	postBodyPayload := map[string]interface{}{
		"username": "test",
		"password": "123456",
	}

	// 生成 x-s 签名 (POST 请求的 x-s 通常也需要新的时间戳)
	xsPost, err := client.SignXS(postMethod, postURI, a1Value, "xhs-pc-web", postBodyPayload, nil)
	if err != nil {
		log.Fatalf("生成 POST x-s 签名失败: %v", err)
	}

	fmt.Printf("x-s: %s\n", xsPost)
	fmt.Printf("x-t: %d\n", client.GetXT(nil)) // 新的 x-t
	fmt.Printf("x-b3-traceid: %s\n", client.GetB3TraceId()) // 新的 b3-traceid
	fmt.Printf("x-xray-traceid: %s\n", client.GetXrayTraceId(nil, nil)) // 新的 xray-traceid
	fmt.Printf("x-s-common: %s\n\n", xsCommon) // x-s-common 可以复用或重新生成

	// --------------------------------------------------
	// 3. 解密与验证 (以 GET 请求生成的 x-s 为例)
	// --------------------------------------------------
	fmt.Println("--- x-s 解密示例 ---")
	sigData, err := client.DecodeXS(xsGet)
	if err != nil {
		log.Printf("解密 x-s 失败: %v\n", err)
	} else {
		fmt.Printf("解密后的 x-s 数据结构 (部分): %+v\n", sigData)

		// 解密 x3 字段并解析其载荷
		if sigData != nil && sigData.X3 != "" {
			x3Decoded, err := client.DecodeX3(sigData.X3)
			if err != nil {
				log.Printf("解密 x3 失败: %v\n", err)
			} else {
				fmt.Printf("解密后的 x3 (原始字节长度): %d\n", len(x3Decoded))

				x3Payload, err := xhshow.ParseX3Payload(x3Decoded)
				if err != nil {
					log.Printf("解析 x3 载荷失败: %v\n", err)
				} else {
					fmt.Printf("解析出的 X3 载荷详情:\n")
					fmt.Printf("  版本 (Version): %d\n", x3Payload.Version)
					fmt.Printf("  原始时间戳 (TimestampRaw): %d\n", x3Payload.TimestampRaw)
					fmt.Printf("  URI长度 (UriLen): %d\n", x3Payload.UriLen)
					fmt.Printf("  A1 Cookie: %s\n", x3Payload.A1)
					// ... 更多字段 ...
				}
			}
		}
	}
}
```

## API 参考

`xhshow-go` 提供了 `Client` 结构体作为主要入口，用于生成各种签名和辅助信息。

### `Client` 核心方法

*   **`NewClient() *Client`**
    *   创建一个新的 `xhshow` 客户端实例。这是使用库功能的起点。

*   **`SignXS(method, uri, a1Value, xsecAppId string, payload map[string]interface{}, timestamp *float64) (string, error)`**
    *   **描述**: 生成 `x-s` 签名。
    *   **参数**:
        *   `method`: HTTP 请求方法，例如 `"GET"` 或 `"POST"`。
        *   `uri`: 请求的路径，例如 `"/api/sns/web/v1/user_posted"` (不包含域名和查询参数)。
        *   `a1Value`: `a1` cookie 的值。
        *   `xsecAppId`: (可选) 应用 ID，如果为空则默认为 `"xhs-pc-web"`。
        *   `payload`: (可选) 请求体 (`POST`) 或查询参数 (`GET`) 的 `map[string]interface{}`。
        *   `timestamp`: (可选) 指定 Unix 时间戳（`float64` 秒），如果为 `nil` 则使用当前时间。
    *   **返回值**: `x-s` 签名字符串和 `error`。

*   **`SignXSCommon(cookieDict map[string]interface{}) (string, error)`**
    *   **描述**: 生成 `x-s-common` 签名。
    *   **参数**:
        *   `cookieDict`: 包含 `a1` 和 `web_session` 等 cookie 值的 `map[string]interface{}`。
    *   **返回值**: `x-s-common` 签名字符串和 `error`。

### 辅助工具方法

*   **`GetXT(timestamp *float64) int64`**
    *   **描述**: 获取 `x-t` 头部值（毫秒级 Unix 时间戳）。
    *   **参数**: `timestamp` (可选)，指定 Unix 时间戳（`float64` 秒），如果为 `nil` 则使用当前时间。

*   **`GetB3TraceId() string`**
    *   **描述**: 生成 `x-b3-traceid`。

*   **`GetXrayTraceId(timestamp *int64, seq *int) string`**
    *   **描述**: 生成 `x-xray-traceid`。
    *   **参数**: `timestamp` (可选) 和 `seq` (可选)。

*   **`DecodeXS(xsSignature string) (*SignatureData, error)`**
    *   **描述**: 解密完整的 `x-s` 签名字符串，返回 `SignatureData` 结构。

*   **`DecodeX3(x3Signature string) ([]byte, error)`**
    *   **描述**: 解密 `x-s` 签名中的 `x3` 部分，返回原始字节数组。

*   **`ParseX3Payload(decodedX3 []byte) (*X3Payload, error)`**
    *   **描述**: 解析已解密的 `x3` 字节数据，返回结构化的 `X3Payload` 详情。

## 类型定义

本项目中使用的关键 Go 结构体：

```go
// SignatureData 表示已解码的 x-s 签名的结构。
// 包含 x3 字段及其他可能的元数据。
type SignatureData struct {
	X3 string `json:"x3"`
	// ... 更多字段根据 x-s 实际结构补充 ...
}

// X3Payload 表示从 x3 签名载荷中解析出的详细信息。
type X3Payload struct {
	Version        uint32 `json:"version"`
	Seed           uint32 `json:"seed"`
	TimestampRaw   uint64 `json:"timestamp_raw"`
	Sequence       uint32 `json:"sequence"`
	WindowPropsLen uint32 `json:"window_props_len"`
	UriLen         uint32 `json:"uri_len"`
	Md5Hex         string `json:"md5_hex"` // 请求体/参数 MD5 的十六进制片段
	A1             string `json:"a1"`      // a1 cookie 值
	Source         string `json:"source"`  // 请求来源，如 "xhs-pc-web"
}
```

## 开发

```bash
# 克隆项目
git clone https://github.com/your-username/xhshow-go # 替换为你的仓库地址
cd xhshow-go

# 安装依赖
go mod tidy

# 运行快速开始示例
go run main.go

# 构建可执行文件
go build -o xhshow-go
```

### 项目结构

```
xhshow-go/
├── xhshow/            # 核心签名逻辑和工具包
│   ├── client.go      # `Client` 结构体定义及主要签名方法
│   ├── config.go      # 常量和配置定义
│   ├── cookie_gen.go  # 处理 cookie 相关的逻辑
│   ├── crc32.go       # CRC32 校验码计算
│   ├── crypto.go      # 加密/解密算法实现 (如 XOR 变换, Base64 编码)
│   ├── fingerprint.go # 指纹生成逻辑
│   ├── fp_data.go     # 指纹相关数据
│   ├── fp_helpers.go  # 指纹辅助函数
│   ├── utils.go       # 通用工具函数 (如 URL 提取, Python 风格 Quote)
│   └── xs_common.go   # x-s-common 签名生成逻辑
├── go.mod             # Go 模块定义文件
├── go.sum             # 模块依赖校验和文件
└── main.go            # 快速开始和使用示例
└── README.md          # 项目说明 (当前文件)
```

## 相关项目

-   [Cloxl/xhshow](https://github.com/Cloxl/xhshow) - 原版 Python 实现（本项目上游）

## License

[MIT](LICENSE)
