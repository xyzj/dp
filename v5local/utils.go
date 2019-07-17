package dpv5

import (
	"bytes"
	b64 "encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	msgctl "github.com/xyzj/proto/msgjk"

	"github.com/gogo/protobuf/proto"
	"github.com/xyzj/gopsu"
)

const (
	SockUnkonw = iota
	SockTml
	SockData
	SockClient
	SockSdcmp
	SockFwdcs
	SockUpgrade
	SockIisi
	SockVb6
	SockUDP
)

const (
	SendLevelNormal = iota
	SendLevelHigh
)

const (
	DataTypeUnknow = iota
	DataTypeBytes
	DataTypeString
	DataTypeBase64
)

const (
	JobSend = iota
	JobDo
)

const (
	TraUnknow = iota
	TraDirect
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

const (
	ctlHead = "`"
	tmlHead = "~"
	gpsHead = "$"
	mruHead = "h"
	// SendGpsAT 采集gps信息
	SendGpsAT = "AT+OPENAT=GPSINFO?\r"
	// JSON data head
	JSONData = `{"head":{"mod":2,"src":1,"ver":1,"tver":1,"tra":1,"ret":1,"cmd":""},"args":{"ip":[],"port":0,"addr":[],"cid":1},"data":{}}`
	// 读模块版本信息
	// SendIMEI = "3e-3c-0f-00-30-30-30-30-30-30-30-30-30-30-30-01-20-00-02-a5-18"
)

var (
	SendUdpKA = []byte("Х")
	// Send7004 上海路灯升级准备
	Send7004 = gopsu.String2Bytes("7E-70-18-00-00-00-04-00-57-4A-33-30-30-36-42-5A-2D-31-00-00-3C-00-CC-CC-CC-CC-CC-CC-80-42", "-")
	// Send7010 从终端复位模块
	Send7010 = gopsu.String2Bytes("7e-70-05-00-00-00-10-00-03-30-b2", "-")
	// Send3e3c09 复位模块
	Send3e3c09 = gopsu.String2Bytes("3e-3c-12-0-0-0-0-0-0-0-0-0-0-9-c0-85", "-")
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
	// 远程升级用版本招测
	SendUpg0500 = gopsu.String2Bytes("7e-fe-05-00-00-00-05-00-00-e8-9b", "-")
	// SendGps 采集gps信息
	SendGps = gopsu.String2Bytes("7e-59-4-0-0-0-4-1-cd-22", "-")
	// Send3e3c01
	SendIMEI = gopsu.String2Bytes("3e-3c-0f-00-30-30-30-30-30-30-30-30-30-30-30-01-20-04-02-a7-d8", "-")
	// DirConf config files dir path
	DirConf string
	// DirLog log files dir path
	DirLog string
	// DirCache cache files dir path
	DirCache string
	// NorcClis NorcClis
	NorcClis []int64 // = make([]int64, 0)
	// LegalIPs LegalIPs
	LegalIPs []int64
	// CheckLegalIP  CheckLegalIP
	CheckLegalIP = false
	// append json format back
	AnsJSON = false
)

// 数据解析结果需发送内容结构体
type Fwd struct {
	DataMsg     []byte       // 发送数据
	DataMQ      []byte       // zmq推送数据
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
	Ex          string       // 错误信息
	Src         string       // 原始数据
	Job         byte         // 0-just send,1-need do something else
	Remark      string       // 备注信息，或其他想要传出的数据
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

// GetHelloMsg send who is
func GetHelloMsg() *msgctl.MsgWithCtrl {
	a := int(0)
	return initMsgCtl("wlst.sys.whois", 0, 0, 1, 1, 0, &a)
}

// GetServerTimeMsg
// Args:
// 	t:设备时间格式1-rtu,2-slu,3-vslu,4-esu
// 	nosecond：是否携带秒字节
// 	nocmd：是否需要组装为完整命令
func GetServerTimeMsg(addr int64, t int, nosecond bool, nocmd bool) []byte {
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
	if !nosecond { // 不发秒字节时重复发送周字节
		newdate = append(newdate, byte(dt.Second()))
	} else {
		newdate = append(newdate, byte(dt.Weekday()))
	}
	if nocmd {
		return newdate
	}
	return DoCommand(1, 1, 1, addr, 1, cmd, newdate, 0, 0)
}

// CodePb2 code msgctl
func CodePb2(m *msgctl.MsgWithCtrl) []byte {
	if b, ex := proto.Marshal(m); ex == nil {
		return b
		// return []byte(b64.StdEncoding.EncodeToString(b))
		// return b64.StdEncoding.EncodeToString(b)
	}
	return []byte{}
}

// DecodePb2 decode msgcgtl
// Args:
// 	s: base64编码格式数据
// 	b：pb2序列化数据
// 	两个参数二选一，b为高优先级
func Pb2FromBytes(b []byte) *msgctl.MsgWithCtrl {
	defer func() *msgctl.MsgWithCtrl { return nil }()
	msg := &msgctl.MsgWithCtrl{}
	if ex := proto.Unmarshal(b, msg); ex == nil {
		return msg
	}
	return nil
}

func Pb2FromB64String(s string) *msgctl.MsgWithCtrl {
	defer func() *msgctl.MsgWithCtrl { return nil }()
	if len(s) > 0 {
		if bb, ex := b64.StdEncoding.DecodeString(s); ex == nil {
			msg := &msgctl.MsgWithCtrl{}
			if ex := proto.Unmarshal(bb, msg); ex == nil {
				return msg
			}
		}
	}
	return nil
}

func DecodePb2(s string, b []byte) *msgctl.MsgWithCtrl {
	defer func() *msgctl.MsgWithCtrl { return nil }()
	if b != nil {
		msg := &msgctl.MsgWithCtrl{}
		if ex := proto.Unmarshal(b, msg); ex == nil {
			return msg
		}
	} else if len(s) > 0 {
		if bb, ex := b64.StdEncoding.DecodeString(s); ex == nil {
			msg := &msgctl.MsgWithCtrl{}
			if ex := proto.Unmarshal(bb, msg); ex == nil {
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
				switch tra {
				case 1:
					l := len(data) + 2
					b.WriteByte(0x7e)
					b.WriteByte(0x62)
					b.WriteByte(byte(l))
					b.WriteByte(byte(addr))
					b.WriteByte(cmd2)
					b.Write(data)
					a := b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				case 2:
					var b485 bytes.Buffer
					b485.WriteByte(0x7e)
					b485.WriteByte((0x62))
					b485.WriteByte(byte(len(data) + 2))
					b485.WriteByte(byte(cid))
					b485.WriteByte(cmd2)
					b485.Write(data)
					a := b485.Bytes()
					b485.Write(gopsu.CountCrc16VB(&a))
					b.WriteByte(0x7e)
					b.WriteByte(byte(b485.Len()) + 7)
					b.WriteByte(byte(addr % 256))
					b.WriteByte(byte(addr / 256))
					b.WriteByte(0x37)
					b.WriteByte(br)
					b.WriteByte(rc)
					b.Write(b485.Bytes())
					b.WriteByte(0)
					a = b.Bytes()
					b.WriteByte(gopsu.CountLrc(&a))
					a = b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				}
			case "als":
				switch tra {
				case 1:
					l := len(data) + 3
					b.WriteByte(0x7e)
					b.WriteByte(0x5a)
					b.WriteByte(byte(l))
					b.WriteByte(cmd1)
					b.Write(data)
					a := b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				case 2:
					var b485 bytes.Buffer
					b485.WriteByte(0x7e)
					b485.WriteByte(0x5a)
					b485.WriteByte(byte(len(data) + 3))
					b485.WriteByte(cmd1)
					b485.Write(data)
					a := b485.Bytes()
					b485.Write(gopsu.CountCrc16VB(&a))
					b.WriteByte(0x7e)
					b.WriteByte(byte(b485.Len()) + 7)
					b.WriteByte(byte(addr % 256))
					b.WriteByte(byte(addr / 256))
					b.WriteByte(0x37)
					b.WriteByte(br)
					b.WriteByte(rc)
					b.Write(b485.Bytes())
					b.WriteByte(0)
					a = b.Bytes()
					b.WriteByte(gopsu.CountLrc(&a))
					a = b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				}
			case "esu":
				switch tra {
				case 1:
					l := len(data) + 1
					b.WriteByte(0x7e)
					b.WriteByte(0x80)
					b.WriteByte(byte(l))
					b.WriteByte(cmd1)
					b.Write(data)
					a := b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				case 2:
					var b485 bytes.Buffer
					b485.WriteByte(0x7e)
					b485.WriteByte(0x80)
					b485.WriteByte(byte(len(data) + 1))
					b485.WriteByte(cmd1)
					b485.Write(data)
					a := b485.Bytes()
					b485.Write(gopsu.CountCrc16VB(&a))
					b.WriteByte(0x7e)
					b.WriteByte(byte(b485.Len()) + 7)
					b.WriteByte(byte(addr % 256))
					b.WriteByte(byte(addr / 256))
					b.WriteByte(0x37)
					b.WriteByte(br)
					b.WriteByte(rc)
					b.Write(b485.Bytes())
					b.WriteByte(0)
					a = b.Bytes()
					b.WriteByte(gopsu.CountLrc(&a))
					a = b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				}
			case "ldu":
				switch tra {
				case 1:
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
				case 2:
					var b485 bytes.Buffer
					b485.WriteByte(0x7e)
					b485.WriteByte(byte(len(data) + 5))
					b485.WriteByte(byte(cid % 256))
					b485.WriteByte(byte(cid / 256))
					b485.WriteByte(cmd1)
					b485.Write(data)
					b485.WriteByte(0)
					a := b485.Bytes()
					b485.WriteByte(gopsu.CountLrc(&a))
					a = b485.Bytes()
					b485.Write(gopsu.CountCrc16VB(&a))
					b.WriteByte(0x7e)
					b.WriteByte(byte(b485.Len()) + 7)
					b.WriteByte(byte(addr % 256))
					b.WriteByte(byte(addr / 256))
					b.WriteByte(0x37)
					b.WriteByte(br)
					b.WriteByte(rc)
					b.Write(b485.Bytes())
					b.WriteByte(0)
					a = b.Bytes()
					b.WriteByte(gopsu.CountLrc(&a))
					a = b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				}
			case "slu":
				switch tra {
				case 1:
					l := len(data) + 3
					b.WriteByte(0x7e)
					if cmd1 != 0x90 && cmd2 > 0 {
						b.WriteByte(cmd2)
					} else {
						b.WriteByte(0x90)
					}
					b.WriteByte(byte(l % 256))
					b.WriteByte(byte(l / 256))
					b.WriteByte(byte(addr % 256))
					b.WriteByte(byte(addr / 256))
					if cmd2 > 0 && (cmd1 == 0x71 || cmd1 == 0x72) {
						b.WriteByte(cmd2)
					} else {
						b.WriteByte(cmd1)
					}
					b.Write(data)
					a := b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				case 2:
					var b485 bytes.Buffer
					l := len(data) + 3
					b485.WriteByte(0x7e)
					if cmd1 != 0x90 && cmd2 > 0 {
						b485.WriteByte(cmd2)
					} else {
						b485.WriteByte(0x90)
					}
					b485.WriteByte(byte(l % 256))
					b485.WriteByte(byte(l / 256))
					b485.WriteByte(byte(cid % 256))
					b485.WriteByte(byte(cid / 256))
					b485.WriteByte(cmd1)
					b485.Write(data)
					a := b485.Bytes()
					b485.Write(gopsu.CountCrc16VB(&a))
					b.WriteByte(0x7e)
					b.WriteByte(byte(b485.Len()) + 7)
					b.WriteByte(byte(addr % 256))
					b.WriteByte(byte(addr / 256))
					b.WriteByte(0x37)
					b.WriteByte(br)
					b.WriteByte(rc)
					b.Write(b485.Bytes())
					b.WriteByte(0)
					a = b.Bytes()
					b.WriteByte(gopsu.CountLrc(&a))
					a = b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
				}
			case "mru":
				switch tra {
				case 1:
					b.WriteByte(0xfe)
					b.WriteByte(0xfe)
					b.WriteByte(0xfe)
					b.WriteByte(0xfe)
					b.WriteByte(0x68)
					for k, v := range data {
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
					return b.Bytes()
				case 2:
					var b485 bytes.Buffer
					b485.WriteByte(0xfe)
					b485.WriteByte(0xfe)
					b485.WriteByte(0xfe)
					b485.WriteByte(0xfe)
					b485.WriteByte(0x68)
					for k, v := range data {
						if k == len(data)-1 {
							break
						}
						b485.WriteByte(v)
						if k == 5 {
							b485.WriteByte(0x68)
						}
					}
					a := b485.Bytes()
					l := len(a)
					x := 0
					for i := 4; i < l; i++ {
						x += int(a[i])
					}
					b485.WriteByte(byte(x % 256))
					b485.WriteByte(0x16)
					b485.WriteByte(0)
					a = b485.Bytes()
					b.WriteByte(0x7e)
					b.WriteByte(byte(len(a) + 6))
					b.WriteByte(byte(addr % 256))
					b.WriteByte(byte(addr / 256))
					b.WriteByte(0x37)
					b.WriteByte(br)
					// b.WriteByte(byte(data[len(data)-1]))
					b.WriteByte(rc)
					b.Write(b485.Bytes())
					a = b.Bytes()
					b.WriteByte(gopsu.CountLrc(&a))
					a = b.Bytes()
					b.Write(gopsu.CountCrc16VB(&a))
					return b.Bytes()
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
