package xhshow

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	mrand "math/rand"
	"strconv"
	"strings"
)

// WeightedRandomChoice 根据权重选择一个项目并以字符串形式返回
func WeightedRandomChoice(options interface{}, weights []float64) string {
	// 计算权重总和
	var totalWeight float64
	for _, w := range weights {
		totalWeight += w
	}

	r := mrand.Float64() * totalWeight

	var idx int = -1
	var currentWeight float64
	for i, w := range weights {
		currentWeight += w
		if r <= currentWeight {
			idx = i
			break
		}
	}

	// 如果发生舍入误差或未设置 idx，则回退到最后一项
	if idx == -1 {
		idx = len(weights) - 1
	}

	switch v := options.(type) {
	case []string:
		if idx < len(v) && idx >= 0 {
			return v[idx]
		}
	case []int:
		if idx < len(v) && idx >= 0 {
			return strconv.Itoa(v[idx])
		}
	}
	return ""
}

func GetRendererInfo() (string, string) {
	// 从 GPU_VENDORS 中随机选择
	rendererStr := GpuVendors[mrand.Intn(len(GpuVendors))]
	parts := strings.Split(rendererStr, "|")
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return parts[0], ""
}

type ScreenConfig struct {
	Width       int
	Height      int
	AvailWidth  int
	AvailHeight int
}

func GetScreenConfig() ScreenConfig {
	resStr := WeightedRandomChoice(ScreenResolutions.Resolutions, ScreenResolutions.Weights)
	parts := strings.Split(resStr, ";")
	width, _ := strconv.Atoi(parts[0])
	height, _ := strconv.Atoi(parts[1])

	var availWidth, availHeight int

	// 随机选择 [True, False]
	if mrand.Intn(2) == 1 {
		// True 分支
		deductionStr := WeightedRandomChoice([]int{0, 30, 60, 80}, []float64{0.1, 0.4, 0.3, 0.2})
		deduction, _ := strconv.Atoi(deductionStr)
		availWidth = width - deduction
		availHeight = height
	} else {
		// False 分支
		deductionStr := WeightedRandomChoice([]int{30, 60, 80, 100}, []float64{0.2, 0.5, 0.2, 0.1})
		deduction, _ := strconv.Atoi(deductionStr)
		availWidth = width
		availHeight = height - deduction
	}

	return ScreenConfig{
		Width:       width,
		Height:      height,
		AvailWidth:  availWidth,
		AvailHeight: availHeight,
	}
}

func GenerateCanvasHash() string {
	return CanvasHash
}

func GenerateWebglHash() string {
	b := make([]byte, 32)
	rand.Read(b) // 使用 crypto/rand 获取安全随机字节
	hash := md5.Sum(b)
	return hex.EncodeToString(hash[:])
}
