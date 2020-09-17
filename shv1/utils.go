package shv1

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"sync"

	"github.com/xyzj/gopsu"
)

const (
	// SockUnkonw 未知socket类型
	SockUnkonw = iota
	// SockTml 终端socket类型
	SockTml
	// SockData 数据层socket类型
	SockData
	// SockClient 客户端socket类型
	SockClient
	// SockSdcmp 串口软件socket类型
	SockSdcmp
	// SockFwdcs 前端管理socket类型
	SockFwdcs
	// SockUpgrade 升级程序socket类型
	SockUpgrade
	// SockIisi 接口socket类型
	SockIisi
	// SockVb6 VB6 socket类型
	SockVb6
	// SockUDP UDP socket类型
	SockUDP
)

const (
	// SendLevelNormal 常规发送
	SendLevelNormal = iota
	// SendLevelHigh 插队发送
	SendLevelHigh
)

const (
	// DataTypeUnknow 未知数据类型
	DataTypeUnknow = iota
	// DataTypeBytes 字节数据类型
	DataTypeBytes
	// DataTypeString 字符串数据类型
	DataTypeString
	// DataTypeBase64 base64码数据类型
	DataTypeBase64
)

const (
	// JobSend 普通数据转发任务
	JobSend = iota
	// JobDo 执行任务
	JobDo
)

const (
	// TraUnknow 未知传输方式
	TraUnknow = iota
	// TraDirect 直接传输
	TraDirect
	// Tra485 通过设备485传输
	Tra485
)

// Fwd 数据解析结果需发送内容结构体
type Fwd struct {
	DataMsg     []byte       // 发送数据
	DataCmd     string       // 指令命令
	DataDst     string       // for tml, something like "wlst-rtu-1"
	DataPT      int32        // command protect time
	DataSP      byte         // data send level 0-normal, 1-high
	DataType    byte         // 1-hex,2-string
	DstType     byte         // 0-unknow,1-tml,2-data,3-client,4-sdcmp,5-fwdcs,6-upgrade,7-iisi,8-vb,9-udp
	DstIP       int64        // 目标ip
	DstIMEI     int64        // 目标imei
	DataUDPAddr *net.UDPAddr // for udp only
	Tra         byte         // 1-socket, 2-485
	Addr        int64        // 设备地址
	Area        string       // 设备区域码
	Ex          string       // 错误信息
	Src         string       // 原始数据
	Job         byte         // 0-just send,1-need do something else
	Remark      string       // 备注信息，或其他想要传出的数据
	DataSrc     *[]byte      // 传递数据
}

// Rtb 数据解析结果
type Rtb struct {
	Do         []*Fwd // 需要进行的操作
	RemoteAddr string // 远程地址
	CliID      uint64 // socket id
	Unfinish   []byte // 未完结数据
	Ex         string // 错误信息
	Src        string // 原始数据
}

func getPnFn(b []byte) int32 {
	var idx int32
	if b[0] == 0 {
		idx = 0
	} else {
		idx = int32(math.Log2(float64(b[0]))) + 1
	}
	return int32(b[1])*8 + idx
}

func setPnFn(n int32) []byte {
	if n == 0 {
		return []byte{0, 0}
	}
	return []byte{byte(math.Exp2(float64(n%8 - 1))), byte(n / 8)}
}

// DataProcessor 数据处理
type DataProcessor struct {
	// Version 协议版本，1,2
	Version int
	// LocalPort 本地监听端口
	LocalPort int
	// RemoteIP 远端ip
	RemoteIP int64
	// imei
	Imei int64
	// Verbose 其他信息
	Verbose sync.Map
	// AreaCode 区域码
	AreaCode string
	// PhyID
	PhyID int64
	// ec1
	Ec1 byte
	// ec2
	Ec2 byte
	// 日志
	Logger gopsu.Logger
}

// BuildCommand 创建命令
// 	addr: 地址
// 	prm: 启动标志位0-应答，1-主动下行
// 	crypt: 是否加密0 为不加密(身份认∕否认(证及密钥协商用到),调整1 代表明文加 MAC,2 代表密文加 MAC,3 密码信封(证书方式)
// 	ver: 版本，1
// 	afn: 应用层功能码
//	con: 是否需要设备应答0-不需要，1-需要
// 	seq: 序号，中间层提供
func (dp *DataProcessor) BuildCommand(data []byte, addr int64, prm, afn, con, seq int32) []byte {
	var b, d bytes.Buffer
	// 地址
	d.Write(gopsu.Float642BcdBytes(float64(addr), "%016.0f"))
	// afn
	d.WriteByte(gopsu.String2Int8(fmt.Sprintf("0%d0%05b", prm, afn), 2))
	// seq
	d.WriteByte(gopsu.String2Int8(fmt.Sprintf("011%d%04b", con, seq), 2))
	// 数据体，含pn，fn
	d.Write(data)
	// 数据体长度
	dd := d.Bytes()
	ll := len(dd)
	d.Write(gopsu.CountCrc16VB(&dd))
	// 整体指令
	b.Write([]byte{0x68, byte(ll % 256), byte(ll / 256), byte(ll % 256), byte(ll / 256),   0x68})
	b.Write(d.Bytes())
	b.WriteByte(0x16)
	return b.Bytes()
}

func decodeBCDA2(b []byte) float64 {
	d := gopsu.String2Int64(fmt.Sprintf("%02x%02x", b[1], b[0])[1:], 10)
	gx := fmt.Sprintf("%03b", b[1]>>5)
	s := b[1] << 3 >> 7
	if s == 1 {
		d = d * -1
	}
	switch gx {
	case "000":
		return float64(d) * 10000
	case "001":
		return float64(d) * 1000
	case "010":
		return float64(d) * 100
	case "011":
		return float64(d) * 10
	case "100":
		return float64(d)
	case "101":
		return float64(d) / 10.0
	case "110":
		return float64(d) / 100.0
	case "111":
		return float64(d) / 1000.0
	}
	return float64(d)
}

func decodeBCDA5(b []byte) float64 {
	return gopsu.BcdBytes2Float64(b, 1, false)
}

