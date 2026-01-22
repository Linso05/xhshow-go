package xhshow

// 配置常量
const (
	Max32Bit       = 0xFFFFFFFF
	MaxSigned32Bit = 0x7FFFFFFF
	MaxByte        = 255

	StandardBase64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	CustomBase64Alphabet   = "ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5"
	X3Base64Alphabet       = "MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G"

	HexKey = "71a302257793271ddd273bcee3e4b98d9d7935e1da33f5765e2ea8afb6dc77a51a499d23b67c20660025860cbf13d4540d92497f58686c574e508f46e1956344f39139bf4faf22a3eef120b79258145b2feb5193b6478669961298e79bedca646e1a693a926154a5a7a1bd1cf0dedb742f917a747a1e388b234f2277"

	SequenceValueMin       = 15
	SequenceValueMax       = 50
	WindowPropsLengthMin   = 900
	WindowPropsLengthMax   = 1200

	ChecksumVersion = 1
	ChecksumXorKey  = 115

	EnvFingerprintXorKey        = 41
	EnvFingerprintTimeOffsetMin = 10
	EnvFingerprintTimeOffsetMax = 50

	X3Prefix  = "mns0301_"
	XysPrefix = "XYS_"

	HexChars                  = "abcdef0123456789"
	XrayTraceIdSeqMax         = 8388607
	XrayTraceIdTimestampShift = 23
	XrayTraceIdPart1Length    = 16
	XrayTraceIdPart2Length    = 16
	B3TraceIdLength           = 16
)

var (
	VersionBytes      = []byte{119, 104, 96, 41}
	ChecksumFixedTail = []byte{249, 65, 103, 103, 201, 181, 131, 99, 94, 7, 68, 250, 132, 21}
)

type SignatureData struct {
	X0 string `json:"x0"`
	X1 string `json:"x1"`
	X2 string `json:"x2"`
	X3 string `json:"x3"`
	X4 string `json:"x4"`
}

func NewSignatureData() SignatureData {
	return SignatureData{
		X0: "4.2.6",
		X1: "xhs-pc-web",
		X2: "Windows",
		X3: "",
		X4: "",
	}
}
