package main

import (
	"fmt"
	"xhshow-go/xhshow"
)

func main() {
	client := xhshow.NewClient()

	// 1. 获取 x-t (时间戳)
	xt := client.GetXT(nil)

	// 2. 获取 x-b3-traceid
	b3TraceId := client.GetB3TraceId()

	// 3. 获取 x-xray-traceid
	xrayTraceId := client.GetXrayTraceId(nil, nil)

	// ==========================================
	// 示例 1: GET 请求生成 x-s
	// ==========================================
	method := "GET"
	uri := "/api/sns/web/v1/user_posted"
	a1 := "efda9b010000220000009d04000022000" // 这里必须替换为 cookie 中的真实 a1 值

	// GET 请求 Payload (查询参数)
	payload := map[string]interface{}{
		"num": 30,
	}

	// 生成 x-s 签名 (GET)
	// 参数: method, uri, a1, xsecAppId (空则默认), payload, timestamp (nil 则使用当前时间)
	xsGet, err := client.SignXS(method, uri, a1, "", payload, nil)
	if err != nil {
		fmt.Printf("生成 x-s 签名失败 (GET): %v\n", err)
		return
	}

	// 5. 生成 x-s-common
	cookies := map[string]interface{}{
		"a1": a1,
	}
	xsCommon, err := client.SignXSCommon(cookies)
	if err != nil {
		fmt.Printf("生成 x-s-common 失败: %v\n", err)
		return
	}

	// 输出 GET 请求结果
	fmt.Println("--------------------------------------------------")
	fmt.Println("生成的 Headers (GET 请求示例)")
	fmt.Println("--------------------------------------------------")
	fmt.Printf("x-s: %s\n", xsGet)
	fmt.Printf("x-t: %d\n", xt)
	fmt.Printf("x-b3-traceid: %s\n", b3TraceId)
	fmt.Printf("x-xray-traceid: %s\n", xrayTraceId)
	fmt.Printf("x-s-common: %s\n", xsCommon)
	fmt.Println("--------------------------------------------------")

	// ==========================================
	// 示例 2: POST 请求生成 x-s
	// ==========================================
	postMethod := "POST"
	postUri := "/api/sns/web/v1/comment/post"

	// POST 请求 Payload (Body 参数)
	postPayload := map[string]interface{}{
		"note_id":  "64ec1234567890",
		"content":  "不错",
		"at_users": []interface{}{},
	}

	// 生成 x-s 签名 (POST)
	xsPost, err := client.SignXS(postMethod, postUri, a1, "", postPayload, nil)
	if err != nil {
		fmt.Printf("生成 x-s 签名失败 (POST): %v\n", err)
	} else {
		fmt.Println("\n--------------------------------------------------")
		fmt.Println("生成的 Headers (POST 请求示例)")
		fmt.Println("--------------------------------------------------")
		fmt.Printf("x-s: %s\n", xsPost)
		fmt.Printf("x-t: %d\n", client.GetXT(nil)) // POST 请求通常需要新的时间戳
		fmt.Printf("x-b3-traceid: %s\n", b3TraceId)
		fmt.Printf("x-xray-traceid: %s\n", xrayTraceId)
		fmt.Printf("x-s-common: %s\n", xsCommon)
		fmt.Println("--------------------------------------------------")
	}

	// ==========================================
	// 6. 解密与验证 (以 GET 请求生成的 x-s 为例)
	// ==========================================
	fmt.Println("\n正在解密 x-s (GET 请求结果)...")
	sigData, err := client.DecodeXS(xsGet)
	if err != nil {
		fmt.Printf("解密 x-s 失败: %v\n", err)
	} else {
		fmt.Printf("解密后的 x-s 数据结构: %+v\n", sigData)

		// 解密 x3 字段
		x3 := sigData.X3
		fmt.Println("正在解密 x3 字段...")
		x3Decoded, err := client.DecodeX3(x3)
		if err != nil {
			fmt.Printf("解密 x3 失败: %v\n", err)
		} else {
			fmt.Printf("解密后的 x3 (十六进制): %x\n", x3Decoded)

			// 解析 x3 载荷详情
			x3Payload, err := xhshow.ParseX3Payload(x3Decoded)
			if err != nil {
				fmt.Printf("解析 x3 载荷失败: %v\n", err)
			} else {
				fmt.Printf("解析出的 X3 载荷详情:\n")
				fmt.Printf("  版本 (Version): %v\n", x3Payload.Version)
				fmt.Printf("  随机种子 (Seed): %d\n", x3Payload.Seed)
				fmt.Printf("  原始时间戳 (TimestampRaw): %d\n", x3Payload.TimestampRaw)
				fmt.Printf("  序列号 (Sequence): %d\n", x3Payload.Sequence)
				fmt.Printf("  窗口属性长度 (WindowPropsLen): %d\n", x3Payload.WindowPropsLen)
				fmt.Printf("  URI长度 (UriLen): %d\n", x3Payload.UriLen)
				fmt.Printf("  MD5片段 (Md5Hex partial): %s\n", x3Payload.Md5Hex)
				fmt.Printf("  A1 Cookie: %s\n", x3Payload.A1)
				fmt.Printf("  来源 (Source): %s\n", x3Payload.Source)
			}
		}
	}
}
