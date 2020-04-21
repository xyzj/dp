package v6

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"

	"github.com/xyzj/gopsu"
	msgctl "gitlab.local/proto/msgjk"
	msgnb "gitlab.local/proto/msgnb"
)

// 组装端口属性字节
//	br:波特率,300,600,1200,2400,4800,7200,9600,19200
//	stop：停止位0-1位，1-2位
//	rc：是否有校验0-无校验，1-有校验
//	rcodd：是否奇校验0-否（偶校验），1-是
func setRSPort(br, stop, rc, rcodd int) byte {
	var bps = 3
	switch br {
	case 300:
		bps = 0
	case 600:
		bps = 1
	case 1200:
		bps = 2
	case 2400:
		bps = 3
	case 4800:
		bps = 4
	case 7200:
		bps = 5
	case 9600:
		bps = 6
	case 19200:
		bps = 7
	}
	return gopsu.String2Int8(fmt.Sprintf("%03b%1b%1b%1b11", bps, stop, rc, rcodd), 2)
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
	// CheckRC 进行终端数据校验
	CheckRC bool
	// LocalPort 本地监听端口
	LocalPort int
	// RemoteIP 远端ip
	RemoteIP int64
	// TimerNoSec 对时无秒字节
	TimerNoSec bool
	// imei
	Imei int64
	// VerInfo
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

func (dp *DataProcessor) writeEC() {
	ioutil.WriteFile(filepath.Join(gopsu.DefaultCacheDir, "ec", fmt.Sprintf("%s%05d", dp.AreaCode, dp.PhyID)), []byte(fmt.Sprintf("%d,%d", dp.Ec1, dp.Ec2)), 0664)
}

func (dp *DataProcessor) readEC() {
	b, err := ioutil.ReadFile(filepath.Join(gopsu.DefaultCacheDir, "ec", fmt.Sprintf("%s%05d", dp.AreaCode, dp.PhyID)))
	if err != nil {
		dp.Ec1 = 0
		dp.Ec2 = 0
		return
	}
	s := strings.Split(string(b), ",")
	if len(s) != 2 {
		dp.Ec1 = 0
		dp.Ec2 = 0
		return
	}
	dp.Ec1 = gopsu.String2Int8(s[0], 10)
	dp.Ec2 = gopsu.String2Int8(s[1], 10)
}

// BuildCommand 创建命令
// 	addr: 地址
// 	prm: 启动标志位0-应答，1-主动下行
// 	fun: 链路层功能码
// 	crypt: 是否加密0 为不加密(身份认∕否认(证及密钥协商用到),调整1 代表明文加 MAC,2 代表密文加 MAC,3 密码信封(证书方式)
// 	ver: 版本，1
// 	afn: 应用层功能码
//	con: 是否需要设备应答0-不需要，1-需要
// 	seq: 序号，中间层提供
// 	area: 区域码
func (dp *DataProcessor) BuildCommand(data []byte, addr int64, prm, fun, crypt, ver, afn, con, seq int32, area string) []byte {
	var b, d bytes.Buffer
	// 控制码
	d.WriteByte(gopsu.String2Int8(fmt.Sprintf("0%d00%04b", prm, fun), 2))
	// 版本和加密
	d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04b%04b", crypt, ver), 2))
	// 地址
	d.Write(dp.MakeAddr(addr, area))
	// afn
	d.WriteByte(byte(afn))
	// seq
	d.WriteByte(gopsu.String2Int8(fmt.Sprintf("011%d%04b", con, seq), 2))
	// 数据体，含pn，fn
	d.Write(data)
	// 数据体长度
	ll := len(d.Bytes())
	// 整体指令
	b.Write([]byte{0x68, byte(ll % 256), byte(ll / 256), byte(ll % 256), byte(ll / 256), 0x68})
	b.Write(d.Bytes())
	b.WriteByte(dp.CalculateRC(d.Bytes()))
	b.WriteByte(0x16)
	return b.Bytes()
}

// CalculateRC 计算校验值
func (dp *DataProcessor) CalculateRC(d []byte) byte {
	var a byte
	for _, v := range d {
		a += v
	}
	return a
}

// MakeAddr 组装国标协议格式地址
func (dp *DataProcessor) MakeAddr(addr int64, area string) []byte {
	var b bytes.Buffer
	if area == "0000" { // 不限定区域，使用设备上行主报区域码
		b.WriteByte(gopsu.Int82Bcd(gopsu.String2Int8(dp.AreaCode[2:], 10)))
		b.WriteByte(gopsu.Int82Bcd(gopsu.String2Int8(dp.AreaCode[:2], 10)))
	} else {
		b.WriteByte(gopsu.Int82Bcd(gopsu.String2Int8(area[2:], 10)))
		b.WriteByte(gopsu.Int82Bcd(gopsu.String2Int8(area[:2], 10)))
	}
	b.WriteByte(byte(addr % 256))
	b.WriteByte(byte(addr / 256))
	if addr == 0xffff {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	return b.Bytes()
}

// Reset 复位
func (dp *DataProcessor) Reset() {
	dp.CheckRC = false
	dp.RemoteIP = 0
	dp.TimerNoSec = false
	dp.Imei = 0
	dp.AreaCode = ""
	dp.Verbose.Range(func(k, v interface{}) bool {
		dp.Verbose.Delete(k)
		return true
	})
}

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

// 通用远程升级指令
var rtuupgrade = []byte{0x81, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88}

// 模块应答指令
var wx2002reply = []byte{0x81, 0x82, 0x83, 0x84}

// 光照度应答指令
var alsreply = []byte{0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xb6, 0xb7, 0xb8, 0xc6, 0xc7, 0xc8, 0xca}

// 3006应答指令
var wj3006reply = []byte{0x82, 0x89, 0xdb, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
	0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
	0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xe0,
	0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec,
	0xed, 0xee, 0xef, 0xd0, 0xda, 0xd3, 0xa1, 0xa2, 0xdb, 0xa3}

// 江阴节能应答指令
var jyesureply = []byte{0xd5, 0xd7, 0xd8}

// 外购漏电
var elureply = []byte{0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xe0, 0xe1, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf}

// 防盗应答指令
var ldureply = []byte{0x96, 0x9a, 0xa6, 0xdb, 0xc9, 0xca, 0xcd, 0xdc}

// 单灯应答指令
var slureply = []byte{0x84, 0x99, 0x9a, 0x9c, 0x9d, 0xa4, 0xa8, 0xb0, 0xb2, 0xcd, 0xd0,
	0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xfd, 0xf6,
	0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfe, 0xff}

// 节能应答指令
var esureply = []byte{0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
	0x9b, 0x9d, 0x9e, 0x9f, 0xa5}

// 3005应答指令
var wj3005replyonly = []byte{
	0x96, // 复位终端应答
	0xa4, // 当天最后开关灯时限应答
	0xa8, // 停运应答
	0xa9, // 取消停运应答
	0xb1, // 1-3周设置应答
	0xb3, // 1-3周设置应答(电台)
	0xc0, // 工作参数应答
	0xc1, // 显示参数应答
	0xc2, // 矢量参数应答
	0xc4, // 上下限参数应答
	0xc6, // 节假日前4时段应答
	// 0xcb,  // 所有回路开关灯应答
	0xce, // 经纬度参数应答
	0xd7, // 发送手机号码应答
	0xd8, // 4-6周设置应答
	0xe1, // 电压参数应答
	0xe8, // 7-8周设置应答
	0xe5, // 节假日后4时段应答
}

// 恒杰门禁应答指令
var hjlockreply = []byte{
	0x81, // 设置地址
	0x82, // 读取状态
	0x83, // 开锁
	0x84, // 关锁
	0x85, // 设置启动提醒参数
	0x86, // 添加卡
	0x87, // 删除卡
	0x88, // 设置管理卡
	0x89, // 重启
	0x8a, // 恢复出厂
	0x8b, // 读取一个卡号
	0x8c, // 设置开锁时间
	0x8d, // 设置刷卡主报
	0x8e, // 刷卡主报
}

const (
	ctlHead = "`"
	tmlHead = "~"
	gpsHead = "$"
	mruHead = "h"
	// SendGpsAT 采集gps信息
	SendGpsAT = "AT+OPENAT=GPSINFO?\r"
	// JSONData data head
	JSONData = `{"head":{"mod":2,"src":1,"ver":1,"tver":1,"tra":1,"ret":1,"cmd":""},"args":{"ip":[],"port":0,"addr":[],"cid":1},"data":{}}`
	// 读模块版本信息
	// SendIMEI = "3e-3c-0f-00-30-30-30-30-30-30-30-30-30-30-30-01-20-00-02-a5-18"
)

var (
	// SendUDPKA udp心跳数据
	SendUDPKA = []byte("Х")
	// Send7004 上海路灯升级准备
	Send7004 = gopsu.String2Bytes("7E-70-18-00-00-00-04-00-57-4A-33-30-30-36-42-5A-2D-31-00-00-3C-00-CC-CC-CC-CC-CC-CC-80-42", "-")
	// Send7010 从终端复位模块
	Send7010 = gopsu.String2Bytes("7e-70-05-00-00-00-10-00-03-30-b2", "-")
	// Send3e3c09 复位模块
	Send3e3c09 = gopsu.String2Bytes("3e-3c-0c-0-30-30-30-30-30-30-30-30-30-30-30-09-58-c9", "-")
	// Send6813 电表读地址
	Send6813 = gopsu.String2Bytes("fe-fe-fe-fe-68-aa-aa-aa-aa-aa-aa-68-13-0-df-16", "-")
	// Send9050 单灯读版本
	Send9050 = gopsu.String2Bytes("7e-90-3-0-0-0-50-dc-6b", "-")
	// Send5a4a 招测光照度软件版本
	Send5a4a = gopsu.String2Bytes("7e-5a-5-4a-0-0-73-12", "-")
	// Send4d00 招测线路监测阻抗基准
	Send4d00 = gopsu.String2Bytes("7e-7-0-0-4d-1-1-0-34-1f-51", "-")
	// Send1800 开机申请应答
	Send1800 = gopsu.String2Bytes("7e-5-0-0-18-0-63-45-7c", "-")
	// Send1400 终端主动报警应答
	Send1400 = gopsu.String2Bytes("7e-5-0-0-14-0-6f-85-7a", "-")
	// Send1500 线路检测主动报警应答
	Send1500 = gopsu.String2Bytes("7e-5-0-0-15-0-6e-15-7a", "-")
	// Send2b00 招测终端序列号
	Send2b00 = gopsu.String2Bytes("7e-5-0-0-2b-0-50-f5-66", "-")
	// Send2000 选测
	Send2000 = gopsu.String2Bytes("7e-5-0-0-20-0-5b-c5-63", "-")
	// Send1300 招测时间
	Send1300 = gopsu.String2Bytes("7e-5-0-0-13-0-68-75-79", "-")
	// Send3200 招测周设置1-3
	Send3200 = gopsu.String2Bytes("7e-5-0-0-32-0-49-e5-6b", "-")
	// Send5900 招测周设置4-6
	Send5900 = gopsu.String2Bytes("7e-5-0-0-59-0-22-d5-58", "-")
	// Send6900 招测周设置7-8
	Send6900 = gopsu.String2Bytes("7e-5-0-0-69-0-12-d5-43", "-")
	// Send6600 招测节假日后4段
	Send6600 = gopsu.String2Bytes("7E-5-0-0-66-0-1d-a5-44", "-")
	// Send5a00 招测终端参数
	Send5a00 = gopsu.String2Bytes("7e-5-0-0-5a-0-21-65-59", "-")
	// Send5b00 招测检测参数
	Send5b00 = gopsu.String2Bytes("7e-5-0-0-5b-0-20-f5-59", "-")
	// Send5c00 招测软件版本
	Send5c00 = gopsu.String2Bytes("7e-5-0-0-5c-0-27-5-5a", "-")
	// Send5f00 召测终端参数k7-k8
	Send5f00 = gopsu.String2Bytes("7e-5-0-0-5f-0-24-b5-5b", "-")
	// SendJY58 江阴节能主报应答
	SendJY58 = gopsu.String2Bytes("7e-16-0-0-37-7e-d0-1-58-f7-0-0-0-0-0-0-0-0-0-0-0-0-0-5f-33-81", "-")
	// SendEsu1c00 节电器主动报警应答
	SendEsu1c00 = gopsu.String2Bytes("7e-d-0-0-37-7e-80-1-1c-19-bd-0-3-35-bd", "-")
	// SendEsu1300 节电器选测
	SendEsu1300 = gopsu.String2Bytes("7e-d-0-0-37-7e-80-1-13-59-b9-0-48-75-8a", "-")
	// SendEsu2600 节电器gprs主动告警应答
	SendEsu2600 = gopsu.String2Bytes("7e-b-0-0-1b-7e-80-1-26-99-ae-0-80-b0-d5", "-")
	// SendAhhf6810 安徽合肥版本召测
	SendAhhf6810 = gopsu.String2Bytes("68-10-0-68-0-0-0-0-0-0-0-0-9-10-0-0-1-0-0-0-f7-b2-56", "-")
	// SendUpg0500 远程升级用版本招测
	SendUpg0500 = gopsu.String2Bytes("7e-fe-05-00-00-00-05-00-00-e8-9b", "-")
	// SendGps 采集gps信息
	SendGps = gopsu.String2Bytes("7e-59-4-0-0-0-4-1-cd-22", "-")
	// SendElu5d00 漏电直连读取参数
	SendElu5d00 = gopsu.String2Bytes("7e-62-02-00-5d-73-8b", "-")
	// SendElu5900 漏电直连读1-4路数据
	SendElu5900 = gopsu.String2Bytes("7e-62-02-00-59-72-48", "-")
	// SendIMEI 读取模块imei
	SendIMEI = gopsu.String2Bytes("3e-3c-0f-00-30-30-30-30-30-30-30-30-30-30-30-01-20-04-02-a7-d8", "-")

	// 国标

	// Resp0902 登录/心跳应答
	Resp0902 = gopsu.String2Bytes("68 0E 00 0E 00 68 0B 01 01 12 04 00 00 00 60 00 00 01 00 02 86 16", " ")
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

// 创建初始化pb2结构
// Args:
// 	cmd: 协议指令
// 	addr: 设备物理地址
// 	ip：远端ip
// 	tver：协议版本，默认1
// 	tra：传输方式，1-socket，2-485
// 	cid: 子设备物理地址
func initMsgCtl(cmd string, addr, ip int64, tver int32, tra byte, cid int32, port *int) *msgctl.MsgWithCtrl {
	msg := &msgctl.MsgWithCtrl{
		Head: &msgctl.Head{
			Mod:  2,
			Src:  1,
			Ver:  1,
			Tver: tver,
			Ret:  0,
			Cmd:  cmd,
			Tra:  int32(tra),
		},
		Args: &msgctl.Args{
			Port: int32(*port),
		},
		WlstTml: &msgctl.WlstTerminal{
			// WlstRtuDc00: &msgctl.WlstRtuDc00{
			// 	Ver: "---",
			// },
		},
		Syscmds: &msgctl.SysCommands{},
	}
	if addr > -1 {
		msg.Args.Addr = append(msg.Args.Addr, addr)
		msg.Args.Ip = append(msg.Args.Ip, ip)
		msg.Args.Cid = cid
	}
	return msg
}

// 创建初始化pb2结构
// Args:
// 	cmd: 协议指令
// 	addr: 设备物理地址
// 	ip：远端ip
// 	tver：协议版本，默认1
// 	tra：传输方式，1-socket，2-485
// 	cid: 子设备物理地址
func initMsgNB(cmd string, addr, imei, at int64) *msgnb.MsgNBOpen {
	msg := &msgnb.MsgNBOpen{
		Imei:          imei,
		DtReceive:     at,
		DataCmd:       cmd,
		SluitemData:   &msgnb.SluitemData{},
		SluitemConfig: &msgnb.SluitemConfig{},
		SluitemReply:  &msgnb.SluitemReply{},
		NbSlu_3100:    &msgnb.NBSlu_3100{},
		NbSlu_3700:    &msgnb.NBSlu_3700{},
		NbSlu_1400:    &msgnb.NBSlu_1400{},
		NbSlu_5100:    &msgnb.NBSlu_5100{},
		NbSlu_5200:    &msgnb.NBSlu_5200{},
		NbSlu_5400:    &msgnb.NBSlu_5400{},
		NbSlu_5500:    &msgnb.NBSlu_5500{},
		NbSlu_5600:    &msgnb.NBSlu_5600{},
	}

	return msg
}

// GetHelloMsg send who is
func GetHelloMsg() *msgctl.MsgWithCtrl {
	a := int(0)
	return initMsgCtl("wlst.sys.whois", 0, 0, 1, 1, 0, &a)
}

// GetServerTimeMsg 按服务器时间组装对时命令
// Args:
// 	t:设备时间格式1-rtu,2-slu,3-vslu,4-esu
// 	oneMoreByte：是否携带秒字节
// 	nocmd：是否需要组装为完整命令
func GetServerTimeMsg(addr int64, t int, oneMoreByte bool, nocmd bool) []byte {
	var newdate = make([]byte, 0, 6)
	var cmd string
	switch t {
	case 1:
		cmd = "wlst.rtu.1200"
	case 2:
		cmd = "wlst.slu.7100"
		newdate = append(newdate, 1, byte(gopsu.String2Int32("00000001", 2)))
	case 3:
		cmd = "wlst.vslu.2100"
		newdate = append(newdate, 2, 0, 0, 0)
	case 4:
		cmd = "wlst.esu.1600"
	}
	dt := time.Now()
	dt = dt.Add(10 * time.Second)
	newdate = append(newdate, byte(dt.Year()-2000),
		byte(dt.Month()),
		byte(dt.Day()),
		byte(dt.Hour()),
		byte(dt.Minute()),
		byte(dt.Weekday()))
	if oneMoreByte { // 发秒字节时重复发送周字节
		newdate = append(newdate, byte(dt.Weekday()))
	}
	if nocmd {
		return newdate
	}
	return DoCommand(1, 1, 1, addr, 1, cmd, newdate, 0, 0)
}

// CodePb2 code msgctl
func CodePb2(m *msgctl.MsgWithCtrl) []byte {
	if b, ex := m.Marshal(); ex == nil {
		return b
		// return []byte(b64.StdEncoding.EncodeToString(b))
		// return b64.StdEncoding.EncodeToString(b)
	}
	return []byte{}
}

// CodePb2NB code msgctl
func CodePb2NB(m *msgnb.MsgNBOpen) []byte {
	if b, ex := m.Marshal(); ex == nil {
		return b
		// return []byte(b64.StdEncoding.EncodeToString(b))
		// return b64.StdEncoding.EncodeToString(b)
	}
	return []byte{}
}

// MsgCtlFromBytes decode MsgWithCtrl
// Args:
// 	b：pb2序列化数据
func MsgCtlFromBytes(b []byte) *msgctl.MsgWithCtrl {
	defer func() *msgctl.MsgWithCtrl { return nil }()
	msg := &msgctl.MsgWithCtrl{}
	if ex := msg.Unmarshal(b); ex == nil {
		return msg
	}
	return nil
}

// MsgFromBytes decode protomsg
// Args:
// 	b：pb2序列化数据
//	pb: proto结构体
func MsgFromBytes(b []byte, pb proto.Message) proto.Message {
	err := proto.Unmarshal(b, pb)
	if err != nil {
		return nil
	}
	return pb
}

// MsgCtlFromB64Str 从base64字符串解析pb2格式数据
func MsgCtlFromB64Str(s string) *msgctl.MsgWithCtrl {
	defer func() *msgctl.MsgWithCtrl { return nil }()
	if len(s) > 0 {
		if bb, ex := base64.StdEncoding.DecodeString(s); ex == nil {
			msg := &msgctl.MsgWithCtrl{}
			if ex := msg.Unmarshal(bb); ex == nil {
				return msg
			}
		}
	}
	return nil
}

// DoCommand 将数据组装为设备指令
// Args：
// 	ver: 协议版本
// 	tver：内部协议版本
// 	tra：传输方式
// 	addr：设备物理地址
// 	cid：485方式时子设备物理地址
// 	cmd：协议命令
// 	data：数据
// 	br：波特率
// 	rc：校验位
func DoCommand(ver, tver, tra byte, addr int64, cid int32, cmd string, data []byte, br, rc byte) []byte {
	lstcmd := strings.Split(cmd, ".")
	cmd1 := gopsu.String2Int8(lstcmd[2][:2], 16)
	cmd2 := gopsu.String2Int8(lstcmd[2][2:], 16)
	var b bytes.Buffer
	switch tver {
	case 0, 1, 3: // wlst
		switch lstcmd[0] {
		case "wlst":
			switch lstcmd[1] {
			case "pth":
				return data
			case "com":
				switch cmd1 {
				case 0x70, 0x71, 0x51:
					l := len(data) + 3
					b.WriteByte(0x5e)
					b.WriteByte(0x51)
					b.WriteByte(byte(l % 256))
					b.WriteByte(byte(l / 256))
					b.WriteByte(byte(addr % 256))
					b.WriteByte(byte(addr / 256))
					b.WriteByte(cmd2)
					b.Write(data)
					a := b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				case 0x3e:
					l := len(data) + 12
					b.WriteByte(0x3e)
					b.WriteByte(0x3c)
					b.WriteByte(byte(l % 256))
					b.WriteByte(byte(l / 256))
					b.Write([]byte{0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30})
					b.WriteByte(cmd2)
					b.Write(data)
					a := b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				default:
					b.WriteByte(0x3c)
					b.WriteByte(cmd2)
					b.Write(data)
					b.WriteByte(0x20)
					a := b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				}
			case "rtu":
				switch cmd1 {
				case 0x70, 0x71, 0x72:
					l := len(data) + 3
					b.WriteByte(0x7e)
					b.WriteByte(cmd1)
					b.WriteByte(byte(l % 256))
					b.WriteByte(byte(l / 256))
					b.WriteByte(byte(addr % 256))
					b.WriteByte(byte(addr / 256))
					b.WriteByte(cmd2)
					b.Write(data)
					a := b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				default:
					l := len(data) + 4
					b.WriteByte(0x7e)
					b.WriteByte(byte(l + 1))
					b.WriteByte(byte(addr % 256))
					b.WriteByte(byte(addr / 256))
					b.WriteByte(cmd1)
					b.Write(data)
					b.WriteByte(0)
					a := b.Bytes()
					b.WriteByte(gopsu.CountLrc(&a))
					a = b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				}
			case "elu":
				devaddr := addr
				if tra == 2 {
					devaddr = int64(cid)
				}
				b.WriteByte(0x7e)
				b.WriteByte(0x62)
				b.WriteByte(byte(len(data) + 2))
				b.WriteByte(byte(devaddr))
				b.WriteByte(cmd2)
				b.Write(data)
				a := b.Bytes()
				b.Write(gopsu.CountCrc16VB(&a))
				switch tra {
				case 1:
					return b.Bytes()
				case 2:
					var b485 bytes.Buffer
					b485.WriteByte(0x7e)
					b485.WriteByte(byte(b.Len()) + 7)
					b485.WriteByte(byte(addr % 256))
					b485.WriteByte(byte(addr / 256))
					b485.WriteByte(0x37)
					b485.WriteByte(br)
					b485.WriteByte(rc)
					b485.Write(b.Bytes())
					b485.WriteByte(0)
					a = b485.Bytes()
					b485.WriteByte(gopsu.CountLrc(&a))
					a = b485.Bytes()
					b485.Write(gopsu.CountCrc16VB(&a))
					return b485.Bytes()
				}
			case "als":
				b.WriteByte(0x7e)
				b.WriteByte(0x5a)
				b.WriteByte(byte(len(data) + 3))
				b.WriteByte(cmd1)
				b.Write(data)
				a := b.Bytes()
				b.Write(gopsu.CountCrc16VB(&a))
				switch tra {
				case 1:
					return b.Bytes()
				case 2:
					var b485 bytes.Buffer
					b485.WriteByte(0x7e)
					b485.WriteByte(byte(b.Len()) + 7)
					b485.WriteByte(byte(addr % 256))
					b485.WriteByte(byte(addr / 256))
					b485.WriteByte(0x37)
					b485.WriteByte(br)
					b485.WriteByte(rc)
					b485.Write(b.Bytes())
					b485.WriteByte(0)
					a = b485.Bytes()
					b485.WriteByte(gopsu.CountLrc(&a))
					a = b485.Bytes()
					b485.Write(gopsu.CountCrc16VB(&a))
					return b485.Bytes()
				}
			case "esu":
				b.WriteByte(0x7e)
				b.WriteByte(0x80)
				b.WriteByte(byte(len(data) + 1))
				b.WriteByte(cmd1)
				b.Write(data)
				a := b.Bytes()
				b.Write(gopsu.CountCrc16VB(&a))
				switch tra {
				case 1:
					return b.Bytes()
				case 2:
					var b485 bytes.Buffer
					b485.WriteByte(0x7e)
					b485.WriteByte(byte(b.Len()) + 7)
					b485.WriteByte(byte(addr % 256))
					b485.WriteByte(byte(addr / 256))
					b485.WriteByte(0x37)
					b485.WriteByte(br)
					b485.WriteByte(rc)
					b485.Write(b.Bytes())
					b485.WriteByte(0)
					a = b485.Bytes()
					b485.WriteByte(gopsu.CountLrc(&a))
					a = b485.Bytes()
					b485.Write(gopsu.CountCrc16VB(&a))
					return b485.Bytes()
				}
			case "ldu":
				devaddr := addr
				if tra == 2 {
					devaddr = int64(cid)
				}
				b.WriteByte(0x7e)
				b.WriteByte(byte(len(data) + 5))
				b.WriteByte(byte(devaddr % 256))
				b.WriteByte(byte(devaddr / 256))
				b.WriteByte(cmd1)
				b.Write(data)
				b.WriteByte(0)
				a := b.Bytes()
				b.WriteByte(gopsu.CountLrc(&a))
				a = b.Bytes()
				b.Write(gopsu.CountCrc16VB(&a))
				switch tra {
				case 1:
					return b.Bytes()
				case 2:
					var b485 bytes.Buffer
					b485.WriteByte(0x7e)
					b485.WriteByte(byte(b.Len()) + 7)
					b485.WriteByte(byte(addr % 256))
					b485.WriteByte(byte(addr / 256))
					b485.WriteByte(0x37)
					b485.WriteByte(br)
					b485.WriteByte(rc)
					b485.Write(b.Bytes())
					b485.WriteByte(0)
					a = b485.Bytes()
					b485.WriteByte(gopsu.CountLrc(&a))
					a = b485.Bytes()
					b485.Write(gopsu.CountCrc16VB(&a))
					return b485.Bytes()
				}
			case "slu":
				devaddr := addr
				if tra == 2 {
					devaddr = int64(cid)
				}
				l := len(data) + 3
				b.WriteByte(0x7e)
				if cmd1 != 0x90 && cmd2 > 0 {
					b.WriteByte(cmd2)
				} else {
					b.WriteByte(0x90)
				}
				b.WriteByte(byte(l % 256))
				b.WriteByte(byte(l / 256))
				b.WriteByte(byte(devaddr % 256))
				b.WriteByte(byte(devaddr / 256))
				if cmd2 > 0 && (cmd1 == 0x71 || cmd1 == 0x72) {
					b.WriteByte(cmd2)
				} else {
					b.WriteByte(cmd1)
				}
				b.Write(data)
				a := b.Bytes()
				b.Write(gopsu.CountCrc16VB(&a))
				switch tra {
				case 1:
					return b.Bytes()
				case 2:
					var b485 bytes.Buffer
					b485.WriteByte(0x7e)
					b485.WriteByte(byte(b.Len()) + 7)
					b485.WriteByte(byte(addr % 256))
					b485.WriteByte(byte(addr / 256))
					b485.WriteByte(0x37)
					b485.WriteByte(br)
					b485.WriteByte(rc)
					b485.Write(b.Bytes())
					b485.WriteByte(0)
					a = b485.Bytes()
					b485.WriteByte(gopsu.CountLrc(&a))
					a = b485.Bytes()
					b485.Write(gopsu.CountCrc16VB(&a))
					return b485.Bytes()
				}
			case "mru":
				b.WriteByte(0xfe)
				b.WriteByte(0xfe)
				b.WriteByte(0xfe)
				b.WriteByte(0xfe)
				b.WriteByte(0x68)
				for k, v := range data {
					if k == len(data)-1 {
						break
					}
					b.WriteByte(v)
					if k == 5 {
						b.WriteByte(0x68)
					}
				}
				a := b.Bytes()
				l := len(a)
				x := 0
				for i := 4; i < l; i++ {
					x += int(a[i])
				}
				b.WriteByte(byte(x % 256))
				b.WriteByte(0x16)
				switch tra {
				case 1:
					return b.Bytes()
				case 2:
					var b485 bytes.Buffer
					b485.WriteByte(0x7e)
					b485.WriteByte(byte(b.Len() + 6))
					b485.WriteByte(byte(addr % 256))
					b485.WriteByte(byte(addr / 256))
					b485.WriteByte(0x37)
					b485.WriteByte(br)
					// b485.WriteByte(byte(data[len(data)-1]))
					b485.WriteByte(rc)
					b485.Write(b.Bytes())
					a = b485.Bytes()
					b485.WriteByte(gopsu.CountLrc(&a))
					a = b485.Bytes()
					b485.Write(gopsu.CountCrc16VB(&a))
					return b485.Bytes()
				}
			case "vslu":
				b.WriteByte(0x68)
				saddr := fmt.Sprintf("%012d", addr)
				xb := make([]byte, 6, 6)
				for i := 12; i > 0; i -= 2 {
					xb[(12-i)/2] = gopsu.Int82Bcd(gopsu.String2Int8(saddr[i-2:i], 10))
				}
				b.Write(xb)
				var b485 bytes.Buffer
				b.WriteByte(0x68)
				b.WriteByte(0x1c)
				b.WriteByte(byte(len(data) + 7))
				b485.WriteByte(0x7d)
				b485.WriteByte(byte(len(data) + 3))
				b485.WriteByte(0)
				b485.WriteByte(0)
				b485.WriteByte(cmd1)
				b485.Write(data)
				a := b485.Bytes()
				b.Write(b485.Bytes())
				b.Write(gopsu.CountCrc16VB(&a))
				x := 0
				a = b.Bytes()
				l := len(a)
				for i := 0; i < l; i++ {
					x += int(a[i])
				}
				b.WriteByte(byte(x % 256))
				b.WriteByte(0x16)
				return b.Bytes()
			case "nbslu":
				b.Write([]byte{0x68, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x68, 0x1c})
				var b485 bytes.Buffer
				b.WriteByte(byte(len(data) + 7))
				b485.WriteByte(0x7d)
				b485.WriteByte(byte(len(data) + 3))
				b485.WriteByte(0)
				b485.WriteByte(0)
				b485.WriteByte(0x21)
				b485.Write(data)
				a := b485.Bytes()
				b.Write(b485.Bytes())
				b.Write(gopsu.CountCrc16VB(&a))
				x := 0
				a = b.Bytes()
				l := len(a)
				for i := 0; i < l; i++ {
					x += int(a[i])
				}
				b.WriteByte(byte(x % 256))
				b.WriteByte(0x16)
				return b.Bytes()
			case "udp":
				l := len(data) + 3
				b.WriteByte(0x7e)
				b.WriteByte(0x70)
				b.WriteByte(byte(l % 256))
				b.WriteByte(byte(l / 256))
				b.WriteByte(byte(addr % 256))
				b.WriteByte(byte(addr / 256))
				b.WriteByte(cmd2)
				b.Write(data)
				a := b.Bytes()
				b.Write(gopsu.CountCrc16VB(&a))
				return b.Bytes()
			}
		case "wxjy":
			switch lstcmd[1] {
			case "esu":
				switch cmd1 {
				case 0x55, 0x56:
					l := len(data) + 6
					b.WriteByte(0x7e)
					b.WriteByte(byte(l + 1))
					b.WriteByte(byte(addr % 256))
					b.WriteByte(byte(addr / 256))
					b.WriteByte(0x37)
					b.WriteByte(0x7e)
					b.WriteByte(0xd0)
					b.WriteByte(0x13)
					b.WriteByte(0x55)
					b.Write(data)
					a := b.Bytes()
					b.WriteByte(gopsu.CountLrc(&a))
					b.WriteByte(0)
					a = b.Bytes()
					b.WriteByte(gopsu.CountLrc(&a))
					a = b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				case 0x57:
					b := make([]byte, 0, 18)
					b = append(b, []byte{0x7e, 0xd0, 0x1, 0x57}...)
					b = append(b, data...)
					b = append(b, gopsu.CountLrc(&b))
					b = append(b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
					nb := make([]byte, 0, len(b)+10)
					nb = append(nb, []byte{0x7e, byte(len(b) + 1), byte(addr % 256), byte(addr / 256), 0x37, 0x5, 0x37}...)
					nb = append(nb, b...)
					nb = append(nb, gopsu.CountLrc(&nb))
					nb = append(nb, gopsu.CountCrc16VB(&nb)...)
					return nb
				case 0x58:
					b := make([]byte, 0, 18)
					b = append(b, []byte{0x7e, 0xd0, 0x1, 0x58}...)
					b = append(b, gopsu.CountLrc(&b))
					b = append(b, data...)
					b = append(b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
					nb := make([]byte, 0, len(b)+10)
					nb = append(nb, []byte{0x7e, byte(len(b) + 1), byte(addr % 256), byte(addr / 256), 0x37, 0x5, 0x0}...)
					nb = append(nb, b...)
					nb = append(nb, gopsu.CountLrc(&nb))
					nb = append(nb, gopsu.CountCrc16VB(&nb)...)
					return nb
				}
			}
		case "hj": // 恒杰门禁
			switch lstcmd[1] {
			case "lock": // 门禁
				devaddr := addr
				if tra == 2 {
					devaddr = int64(cid)
				}
				b.WriteByte(0x68)
				b.WriteByte(byte(devaddr))
				b.WriteByte(cmd1)
				b.WriteByte(byte(len(data)))
				if len(data) > 0 {
					b.Write(data)
				}
				a := b.Bytes()[1:]
				crc := gopsu.CountCrc16VB(&a)
				b.Write([]byte{crc[1], crc[0]})
				b.WriteByte(0x16)
				switch tra {
				case 1:
					return b.Bytes()
				case 2:
					var b485 bytes.Buffer
					b485.WriteByte(0x7e)
					b485.WriteByte(byte(b.Len() + 7))
					b485.WriteByte(byte(addr % 256))
					b485.WriteByte(byte(addr / 256))
					b485.WriteByte(0x37)
					b485.WriteByte(br)
					b485.WriteByte(rc)
					b485.Write(b.Bytes())
					b485.WriteByte(0)
					a = b485.Bytes()
					b485.WriteByte(gopsu.CountLrc(&a))
					a = b485.Bytes()
					b485.Write(gopsu.CountCrc16VB(&a))
					return b485.Bytes()
				}
			}
		}
	case 2: // ahhf
		l := len(data) + 8
		b.WriteByte(0x68)
		b.WriteByte(byte(l % 256))
		b.WriteByte(byte(l / 256))
		b.WriteByte(0x68)
		saddr := fmt.Sprintf("%016d", addr)
		for i := 16; i > 0; i -= 2 {
			b.WriteByte(gopsu.Int82Bcd(gopsu.String2Int8(saddr[i-2:i], 10)))
		}
		b.Write(data)
		a := b.Bytes()[4:]
		b.Write(gopsu.CountCrc16VB(&a))
		return b.Bytes()
	}
	return []byte{}
}

// Single2Tribytes 量程转浮点参数
// 输入：量程，输出：幂指数，尾数高位，尾数低位
func Single2Tribytes(b float64) []byte {
	var e int
	var i float64
	var exponet, mantissah, mantissal int
	in := math.Abs(b)
	if in < math.Exp2(-64) || in > math.Exp2(64)-1 {
		return []byte{0, 0, 0}
	}
	if in >= 0.5 && in < 1 {
		e = 0
		i = in
	} else if in < 0.5 {
		e = 0
		i = in
		for {
			if i < 0.5 {
				i = i * 2
				e = e - 1
			} else {
				break
			}
		}
	} else if in > 1 {
		e = 0
		i = in
		for {
			if i >= 1 {
				i = i / 2
				e = e + 1
			} else {
				break
			}
		}
	}
	if e >= 0 {
		exponet = e
	} else {
		exponet = e + 128
	}
	mantissah = int(i*math.Exp2(16)) / 256
	mantissal = int(math.Ceil(i*math.Exp2(16))) % 256
	return []byte{byte(exponet), byte(mantissah), byte(mantissal)}
}
