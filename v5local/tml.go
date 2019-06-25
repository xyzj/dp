package dpv5

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"github.com/xyzj/gopsu"

	msgctl "192.168.51.60/xy/proto/msgjk"
	pb2 "github.com/gogo/protobuf/proto"
)

// ClassifyTmlData 分类数据解析
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
// 	port：数据服务端口
//  checkrc：是否进行数据校验
// Return:
// 	r: 处理反馈结果
func ClassifyTmlData(d []byte, ip *int64, portlocal, portremote *int, checkrc *bool, oldaddr int64) (r *Rtb) {
	r = &Rtb{}
	defer func() {
		if ex := recover(); ex != nil {
			r.Src = gopsu.Bytes2String(d, "-")
			r.Ex = fmt.Sprintf("%+v", errors.WithStack(ex.(error)))
		}
	}()
LOOP:
	if !bytes.ContainsAny(d, "~{>h^") ||
		(len(d) < 3 && bytes.ContainsAny(d, "<")) || len(d) < 3 {
		return r
	}
	for k, v := range d {
		if len(d)-k <= 3 {
			return r
		}
		switch v {
		case 0x5e: // 新远程升级
			ll := int(d[k+2]) + int(d[k+3])*256
			if ll > 1024 {
				r.Ex = fmt.Sprintf("data too long. %s", gopsu.Bytes2String(d, "-"))
				d = d[k+4:]
				goto LOOP
			}
			if len(d[k:]) < ll+6 {
				r.Ex = fmt.Sprintf("Insufficient data length. %s", gopsu.Bytes2String(d[k:], "-"))
				r.Unfinish = d
				d = []byte{}
				goto LOOP
			}
			r.Do = append(r.Do, dataUpgrade(d[k:k+ll+6], ip, portlocal, oldaddr)...)
			d = d[k+ll+6:]
			goto LOOP
		case 0x7e: // 终端设备等
			l := int(d[k+1])
			if l < 4 {
				d = d[2:]
				goto LOOP
			}
			// 远程升级协议
			if bytes.Contains([]byte{0xfe, 0x70, 0x71, 0x72}, []byte{d[k+1]}) && bytes.Contains(rtuupgrade, []byte{d[k+6]}) {
				ll := int(d[k+2]) + int(d[k+3])*256
				if ll > 1024 {
					r.Ex = fmt.Sprintf("data too long. %s", gopsu.Bytes2String(d, "-"))
					d = d[k+4:]
					goto LOOP
				}
				if len(d[k:]) < ll+6 {
					r.Ex = fmt.Sprintf("Insufficient data length. %s", gopsu.Bytes2String(d[k:], "-"))
					r.Unfinish = d
					d = []byte{}
					goto LOOP
				}
				r.Do = append(r.Do, dataUpgrade(d[k:k+ll+6], ip, portlocal, 0)...)
				d = d[k+ll+6:]
				goto LOOP
			}
			// wj3006协议
			if l == 0x70 && bytes.Contains(wj3006reply, []byte{d[k+6]}) {
				ll := int(d[k+2]) + int(d[k+3])*256
				if ll > 1024 {
					r.Ex = fmt.Sprintf("data too long. %s", gopsu.Bytes2String(d, "-"))
					d = d[k+4:]
					goto LOOP
				}
				if len(d[k:]) < ll+6 {
					r.Ex = fmt.Sprintf("Insufficient data length. %s", gopsu.Bytes2String(d[k:], "-"))
					r.Unfinish = d
					d = []byte{}
					goto LOOP
				}
				// data := d[k : k+ll+6]
				r.Do = append(r.Do, dataRtu70(d[k:k+ll+6], ip, portlocal)...)
				d = d[k+ll+6:]
				goto LOOP
			}
			// 新gps
			if l == 0x59 && bytes.Contains(wx2002reply, []byte{d[k+6]}) {
				ll := int(d[k+2]) + int(d[k+3])*256
				if ll > 1024 {
					r.Ex = fmt.Sprintf("data too long. %s", gopsu.Bytes2String(d, "-"))
					d = d[k+4:]
					goto LOOP
				}
				if len(d[k:]) < ll+6 {
					r.Ex = fmt.Sprintf("Insufficient data length. %s", gopsu.Bytes2String(d[k:], "-"))
					r.Unfinish = d
					d = []byte{}
					goto LOOP
				}
				// data := d[k : k+ll+6]
				r.Do = append(r.Do, dataGps(d[k:k+ll+6], ip, portlocal)...)
				d = d[k+ll+6:]
				goto LOOP
			}
			// 单灯
			if (l == 0x90 && bytes.Contains(slureply, []byte{d[k+6]})) ||
				(bytes.Contains([]byte{0x71, 0x72}, []byte{byte(l)}) &&
					bytes.Contains([]byte{0x81, 0x88, 0x87, 0x86}, []byte{d[k+6]})) {
				ll := int(d[k+2]) + int(d[k+3])*256
				if ll > 1024 {
					r.Ex = fmt.Sprintf("data too long. %s", gopsu.Bytes2String(d, "-"))
					d = d[k+4:]
					goto LOOP
				}
				if len(d[k:]) < ll+6 {
					r.Ex = fmt.Sprintf("Insufficient data length. %s", gopsu.Bytes2String(d[k:], "-"))
					r.Unfinish = d
					d = []byte{}
					goto LOOP
				}
				// data := d[k : k+ll+6]
				r.Do = append(r.Do, dataSlu(d[k:k+ll+6], ip, 1, 0, portlocal)...)
				d = d[k+ll+6:]
				goto LOOP
			}
			// 光照度
			if l == 0x5a && bytes.Contains(alsreply, []byte{d[k+3]}) {
				ll := int(d[k+2])
				if len(d[k:]) < ll+3 {
					r.Ex = fmt.Sprintf("Insufficient data length. %s", gopsu.Bytes2String(d[k:], "-"))
					r.Unfinish = d
					d = []byte{}
					goto LOOP
				}
				// data := d[k : k+ll+3]
				r.Do = append(r.Do, dataAls(d[k:k+ll+3], ip, 1, 0, portlocal)...)
				d = d[k+ll+3:]
				goto LOOP
			}
			// 漏电/主报
			if l == 0xd0 && d[k+3] == 0x62 {
				ll := int(d[k+2])
				if len(d[k:]) < ll+4 {
					r.Ex = fmt.Sprintf("Insufficient data length. %s", gopsu.Bytes2String(d[k:], "-"))
					r.Unfinish = d
					d = []byte{}
					goto LOOP
				}
				// data := d[k : k+ll+4]
				r.Do = append(r.Do, dataElu(d[k:k+ll+4], ip, 1, 0, portlocal)...)
				d = d[k+ll+4:]
				goto LOOP
			}
			if l == 0x7e && bytes.Contains([]byte{0x7e, 0x7b}, []byte{d[k+2]}) {
				d = d[k+2:]
				goto LOOP
			}
			if len(d[k:]) < int(l)+2 {
				r.Ex = fmt.Sprintf("Insufficient data length. %s", gopsu.Bytes2String(d[k:], "-"))
				r.Unfinish = d
				d = []byte{}
				goto LOOP
			}
			if len(d[k:]) >= k+l+4 {
				if bytes.Contains(ldureply, []byte{d[k+4]}) {
					r.Do = append(r.Do, dataLdu(d[k:k+l+4], ip, 1, 0, portlocal)...)
				} else {
					r.Do = append(r.Do, dataRtu(d[k:k+l+4], ip, checkrc, true, portlocal)...)
				}
				// data := d[k : k+l+4]
				d = d[k+l+4:]
				goto LOOP
			} else {
				// data := d[k : k+l+2]
				r.Do = append(r.Do, dataRtu(d[k:k+l+2], ip, checkrc, false, portlocal)...)
				d = d[k+l+2:]
				goto LOOP
			}
		case 0x7b: // 旧版心跳
			if len(d[k:]) < 11 {
				d = []byte{}
			} else {
				p := bytes.Index(d[k+1:], []byte{0x20})
				if p < 11 {
					d = d[k+p+3:]
				} else {
					d = d[k+p+5:]
				}
			}
			goto LOOP
		case 0x3e: // 新版模块
			if d[k+1] == 0x3c {
				l := int(d[k+2]) + int(d[k+3])*256
				if len(d[k:]) < l+6 {
					r.Ex = fmt.Sprintf("Insufficient data length. %s", gopsu.Bytes2String(d[k:], "-"))
					r.Unfinish = d
					d = []byte{}
					goto LOOP
				}
				r.Do = append(r.Do, dataCom(d[k:k+l+6], ip, portlocal, portremote)...)
				d = d[k+l+6:]
				goto LOOP
			} else {
				d = d[k+1:]
				goto LOOP
			}
		case 0x3c: // 旧版模块
			if bytes.Contains([]byte{0x00, 0x01, 0x04, 0x06, 0x08, 0x0c}, []byte{d[k+1]}) {
				// r.Do = append(r.Do, dataCom(d[k:k+3], ip, portlocal, portremote)...)
				d = d[k+3:]
				goto LOOP
			}
			p := bytes.Index(d[k:], []byte{0x20})
			if p > -1 {
				// r.Do = append(r.Do, dataCom(d[k:k+p+2], ip, portlocal, portremote)...)
				d = d[k+p+2:]
				goto LOOP
			} else {
				d = d[k+1:]
				goto LOOP
			}
		case 0x68: // 合肥/电表/勃洛克/上海路灯
			if len(d[k:]) < 12 {
				r.Ex = fmt.Sprintf("Insufficient data length. %s", gopsu.Bytes2String(d[k:], "-"))
				r.Unfinish = d
				d = []byte{}
				goto LOOP
			}
			// 安徽合肥
			lAhhf := int(d[k+1]) + int(d[k+2])*256
			if len(d[k:]) >= lAhhf+7 {
				if d[k+3] == 0x68 && d[k+lAhhf+6] == 0x56 {
					r.Do = append(r.Do, dataAhhf(d[k:k+lAhhf+12], ip, portlocal)...)
					d = d[k+lAhhf+7:]
					goto LOOP
				}
			}
			// 电表/udp单灯
			lMru := int(d[k+9])
			if d[k+7] == 0x68 && d[k+lMru+11] == 0x16 &&
				bytes.Contains([]byte{0x91, 0xd3, 0x93, 0x81, 0x9c}, []byte{d[k+8]}) {
				r.Do = append(r.Do, dataMru(d[k:k+lMru+12], ip, 1, 0, portlocal)...)
				d = d[k+lMru+12:]
				goto LOOP
			}
			// 勃洛克
			lBlk := int(d[k+2])*256 + int(d[k+3])
			if d[k+4] == 0x68 && d[k+lBlk+4] == 0x16 {
				r.Do = append(r.Do, dataBlk(d[k:k+lBlk+12], ip, 1, 0, portlocal)...)
				d = d[k+lMru+12:]
				goto LOOP
			}
			// 上海路灯心跳（无视）
			lShld := int(d[k+1]) + int(d[k+2])*256
			if d[k+5] == 0x68 && d[k+lShld+8] == 0x16 {
				d = d[k+lShld+9:]
				goto LOOP
			}
		}
	}
	return r
}

// NB大平台单灯数据解析
// 	r: 处理反馈结果
func ClassifyNBSluData(d []byte, ip *int64, portlocal, portremote *int, checkrc *bool, oldaddr int64, imei, dataflag string) (r *Rtb) {
	r = ClassifyTmlData(d, ip, portlocal, portremote, checkrc, oldaddr)
	for k, v := range r.Do {
		if v.DstType == SockTml && v.DataCmd == "wlst.vslu.3900" {
			v.DstIMEI = gopsu.String2Int64(imei, 10)
			v.Remark, _ = sjson.Set(v.Remark, "cmdflag", gopsu.String2Int64(dataflag, 10)+55808)
			v.Remark, _ = sjson.Set(v.Remark, "cmdname", "GoWork")
			r.Do[k] = v
		}
	}
	return r
}

// 处理终端数据
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
//  checkrc：是否进行数据校验
//  crc: 是否对lrc失败的数据进行二次crc校验
// Return:
// 	lstf: 处理反馈结果
func dataRtu(d []byte, ip *int64, checkrc *bool, crc bool, portlocal *int) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      TraDirect,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}
	var norc = false
	f.Addr = int64(d[2]) + int64(d[3])*256
	cmd := d[4]

	if !*checkrc || cmd == 0xb7 {
		norc = true
	} else {
		for _, v := range NorcClis {
			if f.Addr == v {
				norc = true
				break
			}
		}
	}
	if !norc {
		p := filepath.Join(DirCache, fmt.Sprintf("rtu-retry-0x20-%d", f.Addr))
		if crc {
			if !gopsu.CheckCrc16VB(d) && !gopsu.CheckLrc(d[:len(d)-2]) {
				f.Ex = fmt.Sprintf("Rtu data validation fails")
				lstf = append(lstf, f)
				_, ex := os.Stat(p)
				if ex == nil {
					os.Remove(p)
				} else {
					os.Create(p)
					if cmd == 0xa0 || cmd == 0xaf {
						ff := &Fwd{
							Addr:     f.Addr,
							DataCmd:  "wlst.rtu.2000",
							DataPT:   3000,
							DataType: DataTypeBytes,
							DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
							DstType:  1,
							Tra:      TraDirect,
							Job:      JobSend,
							Src:      gopsu.Bytes2String(d, "-"),
							DataMsg:  Send2000,
						}
						lstf = append(lstf, ff)
					}
				}
				return lstf
			}
		} else {
			if !gopsu.CheckLrc(d) {
				f.Ex = fmt.Sprintf("Rtu data validation fails")
				lstf = append(lstf, f)
				_, ex := os.Stat(p)
				if ex == nil {
					os.Remove(p)
				} else {
					os.Create(p)
					if cmd == 0xa0 || cmd == 0xaf {
						ff := &Fwd{
							Addr:     f.Addr,
							DataCmd:  "wlst.rtu.2000",
							DataPT:   3000,
							DataType: DataTypeBytes,
							DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
							DstType:  1,
							Tra:      TraDirect,
							Job:      JobSend,
							Src:      gopsu.Bytes2String(d, "-"),
							DataMsg:  Send2000,
						}
						lstf = append(lstf, ff)
					}
				}
				return lstf
			}
		}
	}
	svrmsg := initMsgCtl(fmt.Sprintf("wlst.rtu.%02x00", cmd), f.Addr, *ip, 1, 1, 1, portlocal)
	f.DataCmd = svrmsg.Head.Cmd
	switch cmd {
	case 0xc0, 0xc1, 0xc2, 0xc4: // 参数设置应答
		svrmsg.WlstTml.WlstRtuCxxx = &msgctl.WlstRtu_4111{}
		svrmsg.WlstTml.WlstRtuC111 = &msgctl.WlstRtu_4111{}
		// if (cmd == 0xc1 || cmd == 0xc2) && d[5] != 0xda && d[5] != 0xba { // 依据命令字节后的标识字节设置cmd值，但不兼容3005和旧3006设备
		if cmd == 0xc1 && d[5] == 0x11 { // 针对3006的电能新增协议设置
			svrmsg.Head.Cmd = fmt.Sprintf("wlst.rtu.%02x%02x", cmd, d[5])
			f.DataCmd = svrmsg.Head.Cmd
			if d[6] == 0xda {
				svrmsg.WlstTml.WlstRtuCxxx.Status = 0
				svrmsg.WlstTml.WlstRtuC111.Status = 0
			} else {
				svrmsg.WlstTml.WlstRtuCxxx.Status = 1
				svrmsg.WlstTml.WlstRtuC111.Status = 1
			}
		} else {
			if d[5] == 0xda {
				svrmsg.WlstTml.WlstRtuCxxx.Status = 0
			} else {
				svrmsg.WlstTml.WlstRtuCxxx.Status = 1
			}
		}
		zm := svrmsg.Head
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			if d[5] == 0xda {
				jv, _ = sjson.Set(jv, "data.status", 0)
			} else {
				jv, _ = sjson.Set(jv, "data.status", 1)
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x96, 0xa4, 0xa8, 0xa9, 0xb1, 0xb3, 0xc6, 0xce, 0xd7, 0xd8, 0xe1, 0xe8, 0xe5: // reply only
		zm := svrmsg.Head
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x99: // 改地址
		zm := svrmsg.Head
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		ff := &Fwd{
			// Addr:     f.Addr,
			// DataDst:  fmt.Sprintf("wlst-com-%d", f.Addr),
			DataCmd:  "wlst.com.3e09",
			DataType: DataTypeBytes,
			DataPT:   500,
			DstType:  1,
			Tra:      TraDirect,
			Job:      JobSend,
			DataMsg:  Send3e3c09,
		}
		lstf = append(lstf, ff)
		ff2 := &Fwd{
			Addr:     f.Addr,
			DataCmd:  "wlst.rtu.1000",
			DataType: DataTypeBytes,
			DataPT:   500,
			DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
			DstType:  1,
			Tra:      TraDirect,
			Job:      JobSend,
			DataMsg:  Send7010,
		}
		lstf = append(lstf, ff2)
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xab: // 序列号
		svrmsg.WlstTml.WlstRtuAb00 = &msgctl.WlstRtuDc00{}
		svrmsg.WlstTml.WlstRtuAb00.Ver = string(d[5 : 5+6])
		zm := svrmsg.WlstTml.WlstRtuAb00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.sn", svrmsg.WlstTml.WlstRtuAb00.Ver)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x92: // 对时应答
		// 逻辑上移到中间层
		// ff := &Fwd{
		// 	DataCmd:  "wlst.rtu.1300",
		// 	DataType: DataTypeBytes,
		// 	DataPT:   2000,
		// 	DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
		// 	DstType:  1,
		// 	Tra:      TraDirect,
		// 	Job:      JobSend,
		// 	DataMsg:  Send1300,
		// }
		// lstf = append(lstf, ff)
		zm := svrmsg.Head
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x98: // 开机申请
		svrmsg.WlstTml.WlstRtu_9800 = &msgctl.WlstRtu_9800{}
		svrmsg.WlstTml.WlstRtu_9800.Status = int32(d[5])

		zm := svrmsg.WlstTml.WlstRtu_9800
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		ff := &Fwd{
			Addr:     f.Addr,
			DataCmd:  "wlst.rtu.1800",
			DataType: DataTypeBytes,
			DataPT:   3000,
			DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
			DstType:  1,
			Tra:      TraDirect,
			Job:      JobSend,
			DataMsg:  Send1800,
		}
		lstf = append(lstf, ff)
		// 逻辑上移到中间层
		// ff2 := &Fwd{
		// 	DataCmd:  "wlst.rtu.1200",
		// 	DataType: DataTypeBytes,
		// 	DataPT:   2000,
		// 	DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
		// 	DstType:  1,
		// 	Tra:      TraDirect,
		// 	Job:      JobSend,
		// 	DataMsg:  gopsu.Bytes2String(GetServerTimeMsg(f.Addr, 1, true, false), "-"),
		// }
		// lstf = append(lstf, ff2)

		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.st", int32(d[5]))
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x94: // 终端主报
		f.DataCmd = ""
		zm := svrmsg.Head
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		ff := &Fwd{
			Addr:     f.Addr,
			DataCmd:  "wlst.rtu.2000",
			DataType: DataTypeBytes,
			DataPT:   3000,
			DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
			DstType:  1,
			Tra:      TraDirect,
			Job:      JobSend,
			DataMsg:  Send2000,
		}
		lstf = append(lstf, ff)
	case 0x95: // 线路检测主报
		zm := svrmsg.Head
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		ff := &Fwd{
			Addr:     f.Addr,
			DataCmd:  "wlst.ldu.2600",
			DataType: DataTypeBytes,
			DataPT:   3000,
			DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
			DstType:  1,
			Tra:      TraDirect,
			Job:      JobSend,
			DataMsg:  DoCommand(1, 1, 1, f.Addr, 1, "wlst.ldu.2600", []byte{d[5]}, 2, 5),
			// DataMsg:  gopsu.Bytes2String(DoCommand(1, 1, 1, f.Addr, 1, "wlst.ldu.2600", []byte{d[5]}, 2, 5), "-"),
		}
		lstf = append(lstf, ff)
	case 0xda: // 招测参数
		svrmsg.WlstTml.WlstRtuDa00 = &msgctl.WlstRtuDa00{}
		svrmsg.WlstTml.WlstRtuDa00.KeepAlive = int32(d[5])
		svrmsg.WlstTml.WlstRtuDa00.AlarmCycle = int32(d[6])
		svrmsg.WlstTml.WlstRtuDa00.AlarmDelay = int32(d[7])
		svrmsg.WlstTml.WlstRtuDa00.Addr = int32(f.Addr)
		svrmsg.WlstTml.WlstRtuDa00.SwitchOutSum = int32(d[10])
		svrmsg.WlstTml.WlstRtuDa00.SwitchInSum = int32(d[11])
		svrmsg.WlstTml.WlstRtuDa00.AnalogSum = int32(d[12])
		svrmsg.WlstTml.WlstRtuDa00.XSwitchingTime = append(svrmsg.WlstTml.WlstRtuDa00.XSwitchingTime,
			fmt.Sprintf("%02x%02x-%02x%02x", d[13], d[14], d[19], d[20]),
			fmt.Sprintf("%02x%02x-%02x%02x", d[17], d[18], d[15], d[16]),
			fmt.Sprintf("%02x%02x-%02x%02x", d[21], d[22], d[23], d[24]),
			fmt.Sprintf("%02x%02x-%02x%02x", d[122], d[123], d[124], d[125]),
			fmt.Sprintf("%02x%02x-%02x%02x", d[126], d[127], d[128], d[129]),
			fmt.Sprintf("%02x%02x-%02x%02x", d[130], d[131], d[132], d[133]))
		svrmsg.WlstTml.WlstRtuDa00.CityPayTime = fmt.Sprintf("%02x%02x", d[25], d[26])
		svrmsg.WlstTml.WlstRtuDa00.SelfPayTime = fmt.Sprintf("%02x%02x", d[27], d[28])
		svrmsg.WlstTml.WlstRtuDa00.XSwitchOutCount = append(svrmsg.WlstTml.WlstRtuDa00.XSwitchOutCount, int32(d[30]), int32(d[29]), int32(d[31]), int32(d[79]), int32(d[80]), int32(d[81]))
		svrmsg.WlstTml.WlstRtuDa00.SwitchInHopping = gopsu.String2Int32(fmt.Sprintf("%08b%08b", d[33], d[32]), 2)
		svrmsg.WlstTml.WlstRtuDa00.VoltageRange = int32(d[35]) * 5
		for i := 31; i < 67; i++ {
			svrmsg.WlstTml.WlstRtuDa00.XCurrentRange = append(svrmsg.WlstTml.WlstRtuDa00.XCurrentRange, int32(d[5+i])*5)
		}
		for i := 68; i < 74; i++ {
			svrmsg.WlstTml.WlstRtuDa00.XSwitchOutVector = append(svrmsg.WlstTml.WlstRtuDa00.XSwitchOutVector, int32(d[5+i])+1)
		}
		for i := 77; i < 117; i++ {
			svrmsg.WlstTml.WlstRtuDa00.XSwitchInVector = append(svrmsg.WlstTml.WlstRtuDa00.XSwitchInVector, int32(d[5+i])+1)
		}
		for i := 130; i < 166; i++ {
			svrmsg.WlstTml.WlstRtuDa00.XAnalogVector = append(svrmsg.WlstTml.WlstRtuDa00.XAnalogVector, int32(d[5+i])+1)
		}
		svrmsg.WlstTml.WlstRtuDa00.LowerVoltageLimit = int32(d[171]) * svrmsg.WlstTml.WlstRtuDa00.VoltageRange / 0x3f
		svrmsg.WlstTml.WlstRtuDa00.UpperVoltageLimit = int32(d[172]) * svrmsg.WlstTml.WlstRtuDa00.VoltageRange / 0x3f
		for i := 168; i < 240; i += 2 {
			svrmsg.WlstTml.WlstRtuDa00.XLowerCurrentLimit = append(svrmsg.WlstTml.WlstRtuDa00.XLowerCurrentLimit, int32(float32(d[5+i])/float32(0x3f)*float32(svrmsg.WlstTml.WlstRtuDa00.XCurrentRange[(i-168)/2])))
			svrmsg.WlstTml.WlstRtuDa00.XUpperCurrentLimit = append(svrmsg.WlstTml.WlstRtuDa00.XUpperCurrentLimit, int32(float32(d[6+i])/float32(0x3f)*float32(svrmsg.WlstTml.WlstRtuDa00.XCurrentRange[(i-168)/2])))
		}
		zm := svrmsg.WlstTml.WlstRtuDa00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		ff := &Fwd{
			Addr:     f.Addr,
			DataCmd:  "wlst.rtu.5f00",
			DataType: DataTypeBytes,
			DataPT:   3000,
			DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
			DstType:  1,
			Tra:      TraDirect,
			Job:      JobSend,
			DataMsg:  Send5f00,
		}
		lstf = append(lstf, ff)
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.kl", d[5])
			jv, _ = sjson.Set(jv, "data.ar", d[5+1])
			jv, _ = sjson.Set(jv, "data.ad", d[5+2])
			jv, _ = sjson.Set(jv, "data.addr", f.Addr)
			jv, _ = sjson.Set(jv, "data.lout", d[5+5])
			jv, _ = sjson.Set(jv, "data.lin", d[5+6])
			jv, _ = sjson.Set(jv, "data.sin", d[5+7])
			// k1开时分
			jv, _ = sjson.Set(jv, "data.k1t", fmt.Sprintf("%02x%02x-%02x%02x", d[5+8], d[5+9], d[5+14], d[5+15]))
			jv, _ = sjson.Set(jv, "data.k2t", fmt.Sprintf("%02x%02x-%02x%02x", d[5+12], d[5+13], d[5+10], d[5+11]))
			jv, _ = sjson.Set(jv, "data.k3t", fmt.Sprintf("%02x%02x-%02x%02x", d[5+16], d[5+17], d[5+18], d[5+19]))
			// 市付
			jv, _ = sjson.Set(jv, "data.cpt", fmt.Sprintf("%02x%02x", d[5+20], d[5+21]))
			// 自付
			jv, _ = sjson.Set(jv, "data.spt", fmt.Sprintf("%02x%02x", d[5+22], d[5+23]))
			jv, _ = sjson.Set(jv, "data.l2n", d[5+24])
			jv, _ = sjson.Set(jv, "data.l1n", d[5+25])
			jv, _ = sjson.Set(jv, "data.l3n", d[5+26])
			jv, _ = sjson.Set(jv, "data.l1t", d[5+27])
			jv, _ = sjson.Set(jv, "data.l2t", d[5+28])
			jv, _ = sjson.Set(jv, "data.vr", d[5+30]*5)
			for i := 31; i < 67; i++ {
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%d", i-30), d[5+i]*5)
			}
			for i := 68; i < 74; i++ {
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.lo%d", i-67), d[5+i]+1)
			}
			jv, _ = sjson.Set(jv, "data.l4n", d[5+74])
			jv, _ = sjson.Set(jv, "data.l5n", d[5+75])
			jv, _ = sjson.Set(jv, "data.l6n", d[5+76])
			for i := 77; i < 117; i++ {
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.lin%d", i-76), d[5+i]+1)
			}
			// k4开时分
			jv, _ = sjson.Set(jv, "data.k4t", fmt.Sprintf("%02x%02x-%02x%02x", d[5+117], d[5+118], d[5+119], d[5+120]))
			jv, _ = sjson.Set(jv, "data.k5t", fmt.Sprintf("%02x%02x-%02x%02x", d[5+121], d[5+122], d[5+123], d[5+124]))
			jv, _ = sjson.Set(jv, "data.k6t", fmt.Sprintf("%02x%02x-%02x%02x", d[5+125], d[5+126], d[5+127], d[5+128]))
			for i := 130; i < 166; i++ {
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.sin%d", i-129), d[5+i]+1)
			}
			jv, _ = sjson.Set(jv, "data.vql", d[5+166]*1/0x3f*(d[5+30]*5))
			jv, _ = sjson.Set(jv, "data.vqu", d[5+167]*1/0x3f*(d[5+30]*5))
			for i := 168; i < 240; i += 2 {
				gjv := gjson.Get(jv, fmt.Sprintf("data.l%d", (i-167)/2+1)).Int()
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dql", (i-167)/2+1), int64(d[5+i])*gjv/0x3f)
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dqu", (i-167)/2+1), int64(d[5+i+1])*gjv/0x3f)
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}

	case 0xdf: // 招测参数7-8
		svrmsg.WlstTml.WlstRtuDf00 = &msgctl.WlstRtuDf00{}
		svrmsg.WlstTml.WlstRtuDf00.XSwitchingTime = append(svrmsg.WlstTml.WlstRtuDf00.XSwitchingTime, fmt.Sprintf("%02x%02x-%02x%02x", d[5], d[6], d[7], d[8]), fmt.Sprintf("%02x%02x-%02x%02x", d[9], d[10], d[11], d[12]))
		svrmsg.WlstTml.WlstRtuDf00.XSwitchOutCount = append(svrmsg.WlstTml.WlstRtuDf00.XSwitchOutCount, int32(d[15]), int32(d[16]))
		svrmsg.WlstTml.WlstRtuDf00.XSwitchOutVector = append(svrmsg.WlstTml.WlstRtuDf00.XSwitchOutVector, int32(d[13])+1, int32(d[14])+1)
		zm := svrmsg.WlstTml.WlstRtuDf00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.k7t", fmt.Sprintf("%02x%02x-%02x%02x", d[5], d[5+1], d[5+2], d[5+3]))
			jv, _ = sjson.Set(jv, "data.k8t", fmt.Sprintf("%02x%02x-%02x%02x", d[5+4], d[5+5], d[5+6], d[5+7]))
			jv, _ = sjson.Set(jv, "data.l7n", d[5+10])
			jv, _ = sjson.Set(jv, "data.l8n", d[5+11])
			jv, _ = sjson.Set(jv, "data.lo7", d[5+8]+1)
			jv, _ = sjson.Set(jv, "data.lo8", d[5+9]+1)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xa2: // 开关灯应答
		svrmsg.WlstTml.WlstRtuA200 = &msgctl.WlstRtuA200{}
		svrmsg.WlstTml.WlstRtuA200.KNo = int32(d[5]) + 1
		if d[6] == 0xff {
			svrmsg.WlstTml.WlstRtuA200.Operation = 1
		} else {
			svrmsg.WlstTml.WlstRtuA200.Operation = 0
		}
		zm := svrmsg.WlstTml.WlstRtuA200
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}

		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.k", d[5]+1)
			if d[6] == 0xff {
				jv, _ = sjson.Set(jv, "data.o", 1)
			} else {
				jv, _ = sjson.Set(jv, "data.o", 0)
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xcb: // 组合开关灯应答
		svrmsg.WlstTml.WlstRtuCb00 = &msgctl.WlstRtuAns{}
		svrmsg.WlstTml.WlstRtuCb00.Status = append(svrmsg.WlstTml.WlstRtuCb00.Status, 1)
		zm := svrmsg.WlstTml.WlstRtuCb00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xa0, 0xaf: // 选测
		svrmsg.Head.Cmd = "wlst.rtu.70d0"
		svrmsg.WlstTml.WlstRtu_70D0 = &msgctl.WlstRtu_70D0{}
		svrmsg.WlstTml.WlstRtu_70D0.DataMark = &msgctl.WlstRtu_70D0_DataMark{}
		l := int(d[1])
		loop := 0
		if (l-26)%6 == 0 {
			loop = (l - 26) / 6
		} else if (l-25)%6 == 0 {
			loop = (l - 25) / 6
		} else if (l-24)%6 == 0 {
			loop = (l - 24) / 6
		} else if (l-22)%6 == 0 {
			loop = (l - 22) / 6
		} else if (l-11)%6 == 0 {
			loop = (l - 11) / 6
		}
		svrmsg.WlstTml.WlstRtu_70D0.CmdIdx = -1
		svrmsg.WlstTml.WlstRtu_70D0.DataMark.GetRunData = 1
		j := 5
		fr := 1
		for i := 0; i < loop; i++ {
			sv := &msgctl.WlstRtu_70D0_AnalogData{}
			sv.Voltage = (float64(d[j]) + float64(int32(d[j+1])&0x3f*256)) / 0x3ff0
			sv.VoltageStatus = gopsu.String2Int32(fmt.Sprintf("%08b", d[j+1])[:2], 2)
			j += 2
			sv.Current = (float64(d[j]) + float64(int32(d[j+1])&0x3f*256)) / 0x3ff0
			sv.CurrentStatus = gopsu.String2Int32(fmt.Sprintf("%08b", d[j+1])[:2], 2)
			j += 2
			sv.Power = (float64(d[j]) + float64(int32(d[j+1])&0x3f*256)) / 0x3ff0
			j += 2
			svrmsg.WlstTml.WlstRtu_70D0.AnalogData = append(svrmsg.WlstTml.WlstRtu_70D0.AnalogData, sv)
			if sv.Voltage < 1 || sv.Current < 1 || sv.Power < 1 {
				fr = 0
			}
		}
		ss := gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b%08b%08b", d[j+4], d[j+3], d[j+2], d[j+1], d[j]))
		for _, v := range ss {
			if v == 49 {
				svrmsg.WlstTml.WlstRtu_70D0.SwitchInStPacked = append(svrmsg.WlstTml.WlstRtu_70D0.SwitchInStPacked, 0)
			} else {
				svrmsg.WlstTml.WlstRtu_70D0.SwitchInStPacked = append(svrmsg.WlstTml.WlstRtu_70D0.SwitchInStPacked, 1)
			}
		}
		svrmsg.WlstTml.WlstRtu_70D0.SwitchInSt = gopsu.String2Int64(gopsu.ReverseString(ss), 2) ^ 0xffffffffff
		j += 5
		ss = gopsu.ReverseString(fmt.Sprintf("%08b", d[j]))
		for _, v := range ss {
			svrmsg.WlstTml.WlstRtu_70D0.SwitchOutStPacked = append(svrmsg.WlstTml.WlstRtu_70D0.SwitchOutStPacked, gopsu.String2Int32(string(v), 10))
		}
		svrmsg.WlstTml.WlstRtu_70D0.SwitchOutSt = gopsu.String2Int32(gopsu.ReverseString(ss), 2)
		j++
		ss = gopsu.ReverseString(fmt.Sprintf("%08b", d[j]))
		for _, v := range ss {
			svrmsg.WlstTml.WlstRtu_70D0.TmlStPacked = append(svrmsg.WlstTml.WlstRtu_70D0.TmlStPacked, gopsu.String2Int32(string(v), 10))
		}
		svrmsg.WlstTml.WlstRtu_70D0.TmlSt = gopsu.String2Int32(gopsu.ReverseString(ss), 2)
		j++
		svrmsg.WlstTml.WlstRtu_70D0.Temperature = 0
		if l-(5+loop*6+6) > 7 {
			svrmsg.WlstTml.WlstRtu_70D0.Temperature = int32(d[j])
		}
		svrmsg.WlstTml.WlstRtu_70D0.FullRange = int32(fr)
		// 按王强意见,0x94后的满量程数据写日志后丢弃
		// 逻辑上移到中间层
		// if fr == 0 {
		// 	if fmt.Sprintf("%08b", svrmsg.WlstTml.WlstRtu_70D0.TmlSt)[6] == 49 {
		// 		ff := &Fwd{
		// 			DataCmd:  "wlst.rtu.1200",
		// 			DataType: DataTypeBytes,
		// 			DataPT:   2000,
		// 			DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
		// 			DstType:  1,
		// 			Tra:      TraDirect,
		// 			Job:      JobSend,
		// 			DataMsg:  gopsu.Bytes2String(GetServerTimeMsg(f.Addr, 1, false, false), "-"),
		// 		}
		// 		lstf = append(lstf, ff)
		// 	}
		// }
		zm := svrmsg.WlstTml.WlstRtu_70D0
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xb2: // 招测1-3周设置
		svrmsg.WlstTml.WlstRtuB200 = &msgctl.WlstRtuB200{}
		for i := 0; i < 7; i++ {
			svrmsg.WlstTml.WlstRtuB200.XK1OptTime = append(svrmsg.WlstTml.WlstRtuB200.XK1OptTime, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*16], d[5+i*16+1], d[5+i*16+2], d[5+i*16+3]))
			svrmsg.WlstTml.WlstRtuB200.XK2OptTime = append(svrmsg.WlstTml.WlstRtuB200.XK2OptTime, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*16+4], d[5+i*16+5], d[5+i*16+6], d[5+i*16+7]))
			svrmsg.WlstTml.WlstRtuB200.XK3OptTime = append(svrmsg.WlstTml.WlstRtuB200.XK3OptTime, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*16+8], d[5+i*16+9], d[5+i*16+10], d[5+i*16+11]))
			svrmsg.WlstTml.WlstRtuB200.XCityPayTime = append(svrmsg.WlstTml.WlstRtuB200.XCityPayTime, fmt.Sprintf("%02x%02x", d[5+i*16+12], d[5+i*16+13]))
			svrmsg.WlstTml.WlstRtuB200.XSelfPayTime = append(svrmsg.WlstTml.WlstRtuB200.XSelfPayTime, fmt.Sprintf("%02x%02x", d[5+i*16+14], d[5+i*16+15]))
		}
		ff := &Fwd{
			Addr:     f.Addr,
			DataCmd:  "wlst.rtu.5900",
			DataType: DataTypeBytes,
			DataPT:   3000,
			DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
			DstType:  1,
			Tra:      TraDirect,
			Job:      JobSend,
			DataMsg:  Send5900,
		}
		lstf = append(lstf, ff)
		zm := svrmsg.WlstTml.WlstRtuB200
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			for i := 0; i < 7; i++ {
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.w%dk1", i), fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*16], d[5+i*16+1], d[5+i*16+2], d[5+i*16+3]))
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.w%dk2", i), fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*16+4], d[5+i*16+5], d[5+i*16+6], d[5+i*16+7]))
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.w%dk3", i), fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*16+8], d[5+i*16+9], d[5+i*16+10], d[5+i*16+11]))
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.w%dcp", i), fmt.Sprintf("%02x%02x", d[5+i*16+12], d[5+i*16+13]))
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.w%dsp", i), fmt.Sprintf("%02x%02x", d[5+i*16+14], d[5+i*16+15]))
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xd9: // 招测4-6周设置
		svrmsg.WlstTml.WlstRtuD900 = &msgctl.WlstRtuB200{}
		for i := 0; i < 7; i++ {
			svrmsg.WlstTml.WlstRtuD900.XK4OptTime = append(svrmsg.WlstTml.WlstRtuD900.XK4OptTime, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*12], d[5+i*12+1], d[5+i*12+2], d[5+i*12+3]))
			svrmsg.WlstTml.WlstRtuD900.XK5OptTime = append(svrmsg.WlstTml.WlstRtuD900.XK5OptTime, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*12+4], d[5+i*12+5], d[5+i*12+6], d[5+i*12+7]))
			svrmsg.WlstTml.WlstRtuD900.XK6OptTime = append(svrmsg.WlstTml.WlstRtuD900.XK6OptTime, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*12+8], d[5+i*12+9], d[5+i*12+10], d[5+i*12+11]))
		}
		ff := &Fwd{
			Addr:     f.Addr,
			DataCmd:  "wlst.rtu.6900",
			DataType: DataTypeBytes,
			DataPT:   3000,
			DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
			DstType:  1,
			Tra:      TraDirect,
			Job:      JobSend,
			DataMsg:  Send6900,
		}
		lstf = append(lstf, ff)
		zm := svrmsg.WlstTml.WlstRtuD900
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			for i := 0; i < 7; i++ {
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.w%dk4", i), fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*12], d[5+i*12+1], d[5+i*12+2], d[5+i*12+3]))
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.w%dk5", i), fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*12+4], d[5+i*12+5], d[5+i*12+6], d[5+i*12+7]))
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.w%dk6", i), fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*12+8], d[5+i*12+9], d[5+i*12+10], d[5+i*12+11]))
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xe9: // 招测7-8周设置
		svrmsg.WlstTml.WlstRtuE900 = &msgctl.WlstRtuB200{}
		for i := 0; i < 7; i++ {
			svrmsg.WlstTml.WlstRtuE900.XK7OptTime = append(svrmsg.WlstTml.WlstRtuE900.XK7OptTime, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*8], d[5+i*8+1], d[5+i*8+2], d[5+i*8+3]))
			svrmsg.WlstTml.WlstRtuE900.XK8OptTime = append(svrmsg.WlstTml.WlstRtuE900.XK8OptTime, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*8+4], d[5+i*8+5], d[5+i*8+6], d[5+i*8+7]))
		}
		zm := svrmsg.WlstTml.WlstRtuE900
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			for i := 0; i < 7; i++ {
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.w%dk7", i), fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*8], d[5+i*8+1], d[5+i*8+2], d[5+i*8+3]))
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.w%dk8", i), fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*8+4], d[5+i*8+5], d[5+i*8+6], d[5+i*8+7]))
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xc7, 0xe6: // 招测节假日
		x := &msgctl.WlstRtuE600{}
		var y, z int
		if d[1] > 32*4+7 {
			z = 8
		} else {
			z = 6
		}

		if d[1] > 32*4+7 {
			y = 40
		} else {
			y = 3
		}
		for i := 0; i < 4; i++ {
			x.XHolidays = append(x.XHolidays, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*y+0], d[5+i*y+1], d[5+i*y+2], d[5+i*y+3]))
			for j := 0; j < z; j++ {
				switch j {
				case 0:
					x.XK1Time = append(x.XK1Time, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*y+j*4+4], d[5+i*y+j*4+5], d[5+i*y+j*4+6], d[5+i*y+j*4+7]))
				case 1:
					x.XK2Time = append(x.XK2Time, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*y+j*4+4], d[5+i*y+j*4+5], d[5+i*y+j*4+6], d[5+i*y+j*4+7]))
				case 2:
					x.XK3Time = append(x.XK3Time, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*y+j*4+4], d[5+i*y+j*4+5], d[5+i*y+j*4+6], d[5+i*y+j*4+7]))
				case 3:
					x.XK4Time = append(x.XK4Time, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*y+j*4+4], d[5+i*y+j*4+5], d[5+i*y+j*4+6], d[5+i*y+j*4+7]))
				case 4:
					x.XK5Time = append(x.XK5Time, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*y+j*4+4], d[5+i*y+j*4+5], d[5+i*y+j*4+6], d[5+i*y+j*4+7]))
				case 5:
					x.XK6Time = append(x.XK6Time, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*y+j*4+4], d[5+i*y+j*4+5], d[5+i*y+j*4+6], d[5+i*y+j*4+7]))
				case 6:
					x.XK7Time = append(x.XK7Time, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*y+j*4+4], d[5+i*y+j*4+5], d[5+i*y+j*4+6], d[5+i*y+j*4+7]))
				case 7:
					x.XK8Time = append(x.XK8Time, fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*y+j*4+4], d[5+i*y+j*4+5], d[5+i*y+j*4+6], d[5+i*y+j*4+7]))
				}
			}
			x.XCityPayTime = append(x.XCityPayTime, fmt.Sprintf("%02x%02x", d[5+i*y+28], d[5+i*y+29]))
			x.XSelfPayTime = append(x.XSelfPayTime, fmt.Sprintf("%02x%02x", d[5+i*y+30], d[5+i*y+31]))
		}
		switch cmd {
		case 0xc7:
			svrmsg.WlstTml.WlstRtuC700 = x
			zm := svrmsg.WlstTml.WlstRtuC700
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				f.DataMQ = b
			}
		case 0xe6:
			svrmsg.WlstTml.WlstRtuE600 = x
			zm := svrmsg.WlstTml.WlstRtuE600
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				f.DataMQ = b
			}
		}
		if cmd == 0xc7 {
			ff := &Fwd{
				Addr:     f.Addr,
				DataCmd:  "wlst.rtu.6600",
				DataType: DataTypeBytes,
				DataPT:   3000,
				DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
				DstType:  1,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  Send6600,
			}
			lstf = append(lstf, ff)
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			for i := 0; i < 4; i++ {
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.d%d", i+1), fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*y+0], d[5+i*y+1], d[5+i*y+2], d[5+i*y+3]))
				for j := 0; j < z; j++ {
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.d%dk%d", i+1, j+1), fmt.Sprintf("%02x%02x-%02x%02x", d[5+i*y+j*4+4], d[5+i*y+j*4+5], d[5+i*y+j*4+6], d[5+i*y+j*4+7]))
				}
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.d%dcp", i+1), fmt.Sprintf("%02x%02x", d[5+i*y+28], d[5+i*y+29]))
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.d%dsp", i+1), fmt.Sprintf("%02x%02x", d[5+i*y+30], d[5+i*y+31]))
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x93: // 读终端时间
		svrmsg.WlstTml.WlstRtu_9300 = &msgctl.WlstRtu_9300{}
		svrmsg.WlstTml.WlstRtu_9300.TmlDate = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d %d", int32(d[6])*256+int32(d[5]), d[7], d[8], d[9], d[10], d[11], d[12])
		// 逻辑上移到中间层
		// if math.Abs(float64(gopsu.Time2Stamp(svrmsg.WlstTml.WlstRtu_9300.TmlDate[:19])-time.Now().Unix())) > 60 {
		// 	ff := &Fwd{
		// 		DataCmd:  "wlst.rtu.1200",
		// 		DataType: DataTypeBytes,
		// 		DataPT:   2000,
		// 		DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
		// 		DstType:  1,
		// 		Tra:      TraDirect,
		// 		Job:      JobSend,
		// 		DataMsg:  gopsu.Bytes2String(GetServerTimeMsg(f.Addr, 1, false, false), "-"),
		// 	}
		// 	lstf = append(lstf, ff)
		// }
		zm := svrmsg.WlstTml.WlstRtu_9300
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.date", svrmsg.WlstTml.WlstRtu_9300.TmlDate)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xcc: // 胶南节能设置档位
		svrmsg.WlstTml.WlstRtuCc00 = &msgctl.WlstRtu_9800{}
		switch d[5] {
		case 0xcc:
			svrmsg.WlstTml.WlstRtuCc00.Status = 1
		case 0x55:
			svrmsg.WlstTml.WlstRtuCc00.Status = 2
		case 0x33:
			svrmsg.WlstTml.WlstRtuCc00.Status = 3
		case 0xaa:
			svrmsg.WlstTml.WlstRtuCc00.Status = 4
		default:
			svrmsg.WlstTml.WlstRtuCc00.Status = int32(d[5])
		}

		zm := svrmsg.WlstTml.WlstRtuCc00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}

		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			switch d[5] {
			case 0xcc:
				jv, _ = sjson.Set(JSONData, "data.st", 1)
			case 0x55:
				jv, _ = sjson.Set(JSONData, "data.st", 2)
			case 0x33:
				jv, _ = sjson.Set(JSONData, "data.st", 3)
			case 0xaa:
				jv, _ = sjson.Set(JSONData, "data.st", 4)
			default:
				jv, _ = sjson.Set(JSONData, "data.st", d[5])
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xdc: // 招测终端版本
		svrmsg.WlstTml.WlstRtuDc00 = &msgctl.WlstRtuDc00{}
		svrmsg.WlstTml.WlstRtuDc00.Ver = string(d[5:25])
		if strings.Contains(svrmsg.WlstTml.WlstRtuDc00.Ver, "3090") {
			svrmsg.Head.Cmd = "wlst.ldu.dc00"
			f.DataCmd = "wlst.ldu.dc00"
			svrmsg.WlstTml.WlstLduDc00 = svrmsg.WlstTml.WlstRtuDc00
		}
		ff := &Fwd{
			DataCmd:  svrmsg.Head.Cmd,
			DataType: DataTypeBase64,
			DataDst:  "6",
			DstType:  SockUpgrade,
			Tra:      TraDirect,
			Job:      JobSend,
			Src:      gopsu.Bytes2String(d, "-"),
			DataMsg:  CodePb2(svrmsg),
		}
		lstf = append(lstf, ff)

		zm := svrmsg.WlstTml.WlstRtuDc00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}

		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", 1)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(JSONData, "data.st", string(d[5:25]))
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xf3, 0xb7, 0x9b: // 485
		l := d[1]
		dd := d[5:l]
		if l == 5 || len(dd) < 5 {
			f.Ex = "485 data error"
			lstf = append(lstf, f)
			return lstf
		}
		found := false
		for k, v := range dd {
			switch v {
			case 0x7e:
				if dd[k+1] == 0xd0 { // 485主报 or 江阴节能
					found = true
					return dataD0(dd[k:], ip, 2, f.Addr, portlocal)
				} else if (dd[k+1] == 0x62 || dd[k+2] == 0x62) && bytes.Contains([]byte{0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xe0, 0xe1, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf}, []byte{dd[k+4]}) { // 外购漏电保护
					found = true
					return dataElu(dd[k:], ip, 2, f.Addr, portlocal)
				} else if dd[k+1] == 0x5a { // 光控
					found = true
					return dataAls(dd[k:], ip, 2, f.Addr, portlocal)
				} else if dd[k+1] == 0x90 || dd[k+1] == 0x91 { // 单灯
					found = true
					return dataSlu(dd[k:], ip, 2, f.Addr, portlocal)
				} else if dd[k+1] == 0x80 { // 节能
					found = true
					return dataEsu(dd[k:], ip, 2, f.Addr, portlocal)
				} else if bytes.Contains(ldureply, []byte{dd[k+4]}) {
					found = true
					return dataLdu(dd[k:], ip, 2, f.Addr, portlocal)
				}
			case 0x68:
				if dd[k+7] == 0x68 && bytes.Contains([]byte{0x91, 0xd3, 0x93, 0x81}, []byte{dd[k+8]}) { // 电表
					found = true
					return dataMru(dd[k:], ip, 2, f.Addr, portlocal)
				}
			}
			if !found {
				f.Ex = "Unhandled 485 device protocol"
				lstf = append(lstf, f)
				return lstf
			}
			// if v == 0x7e {
			// 	if dd[k+1] == 0xd0 { // 485主报 or 江阴节能
			// 		return dataD0(dd[k:], ip, 2, f.Addr, portlocal)
			// 	} else if (dd[k+1] == 0x62 || dd[k+2] == 0x62) && bytes.Contains([]byte{0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xe0, 0xe1, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf}, []byte{dd[k+4]}) { // 外购漏电保护
			// 		return dataElu(dd[k:], ip, 2, f.Addr, portlocal)
			// 	} else if dd[k+1] == 0x5a { // 光控
			// 		return dataAls(dd[k:], ip, 2, f.Addr, portlocal)
			// 	} else if dd[k+1] == 0x90 || dd[k+1] == 0x91 { // 单灯
			// 		return dataSlu(dd[k:], ip, 2, f.Addr, portlocal)
			// 	} else if dd[k+1] == 0x80 { // 节能
			// 		return dataEsu(dd[k:], ip, 2, f.Addr, portlocal)
			// 	} else if bytes.Contains(ldureply, []byte{dd[k+4]}) {
			// 		return dataLdu(dd[k:], ip, 2, f.Addr, portlocal)
			// 	}
			// } else if v == 0x68 && dd[k+7] == 0x68 && bytes.Contains([]byte{0x91, 0xd3, 0x93, 0x81}, []byte{dd[k+8]}) { // 电表
			// 	return dataMru(dd, ip, 2, f.Addr, portlocal)
			// } else {
			// 	f.Ex = "Unhandled 485 device protocol"
			// 	lstf = append(lstf, f)
			// 	return lstf
			// }
		}
	case 0xaa:
	case 0xf8: // 招测事件
		svrmsg.Head.Cmd = "wlst.rtu.f800"
		svrmsg.WlstTml.WlstRtuF800 = &msgctl.WlstRtu_7800{}
		svrmsg.WlstTml.WlstRtuF800.EventType = int32(d[5])
		svrmsg.WlstTml.WlstRtuF800.EventClass = int32(d[6])
		svrmsg.WlstTml.WlstRtuF800.AllNum = int32(d[7])
		svrmsg.WlstTml.WlstRtuF800.CurNum = int32(d[8])
		svrmsg.WlstTml.WlstRtuF800.RawData = gopsu.Bytes2String(d, "-")
		zm := svrmsg.WlstTml.WlstRtuF800
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	default:
		f.Ex = fmt.Sprintf("Unhandled rtu protocol: %s", gopsu.Bytes2String(d, "-"))
		lstf = append(lstf, f)
		return lstf
	}

	if len(f.DataCmd) > 0 {
		f.DataCmd = svrmsg.Head.Cmd
		f.DataMsg = CodePb2(svrmsg)
		lstf = append(lstf, f)
	}

	return lstf
}

// 处理3006新0x70标示数据
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
// Return:
// 	lstf: 处理反馈结果
func dataRtu70(d []byte, ip *int64, portlocal *int) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      TraDirect,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}

	if !gopsu.CheckCrc16VB(d) {
		f.Ex = fmt.Sprintf("Rtu data validation fails")
		lstf = append(lstf, f)
		return lstf
	}
	var cmd, ll int32
	cmd = int32(d[6])
	ll = int32(d[3])*256 + int32(d[2])
	f.Addr = int64(d[5])*256 + int64(d[4])
	svrmsg := initMsgCtl(fmt.Sprintf("wlst.rtu.70%02x", cmd), f.Addr, *ip, 1, 1, 1, portlocal)
	f.DataCmd = svrmsg.Head.Cmd
	switch cmd {
	case 0xdb: // 招测硬件相关参数
		svrmsg.Head.Cmd = "wlst.rtu.70db"
		svrmsg.WlstTml.WlstRtu_70Db = &msgctl.WlstRtu_705B{}
		svrmsg.WlstTml.WlstRtu_70Db.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstRtu_70Db.CmdType = int32(d[8])
		j := 9
		switch svrmsg.WlstTml.WlstRtu_70Db.CmdType {
		case 1:
			svrmsg.WlstTml.WlstRtu_70Db.HardwareVer = fmt.Sprintf("V%.1f", float32(d[j])/10)
			j++
			svrmsg.WlstTml.WlstRtu_70Db.ProductionBatch = fmt.Sprintf("%02d%02d", d[j], d[j+1])
			j += 2
			svrmsg.WlstTml.WlstRtu_70Db.ProductionDate = fmt.Sprintf("%04d-%02d-%02d", int(d[j])+2000, d[j+1], d[j+2])
			j += 3
			svrmsg.WlstTml.WlstRtu_70Db.InstallationDate = fmt.Sprintf("%04d-%02d-%02d", int(d[j])+2000, d[j+1], d[j+2])
			j += 3
		}
	case 0xa0: //电能采集/GPS数据
		svrmsg.Head.Cmd = "wlst.rtu.70a0"
		svrmsg.WlstTml.WlstRtu_70A0 = &msgctl.WlstRtu_70A0{}
		svrmsg.WlstTml.WlstRtu_70A0.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstRtu_70A0.CmdType = int32(d[8])
		j := 9
		switch svrmsg.WlstTml.WlstRtu_70A0.CmdType {
		case 1: // 电能数据
			eeA := &msgctl.WlstRtu_70A0_ElectricEnergy{}
			eeB := &msgctl.WlstRtu_70A0_ElectricEnergy{}
			eeC := &msgctl.WlstRtu_70A0_ElectricEnergy{}
			// 电压
			eeA.Voltage = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeB.Voltage = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeC.Voltage = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			// 电流
			eeA.Current = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeB.Current = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeC.Current = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			// 频率
			svrmsg.WlstTml.WlstRtu_70A0.Frequency = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			// 功率因数
			eeA.PowerFactor = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeB.PowerFactor = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeC.PowerFactor = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			// 有功功率
			eeA.ActivePower = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeB.ActivePower = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeC.ActivePower = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			// 无功功率
			eeA.ReactivePower = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeB.ReactivePower = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeC.ReactivePower = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			// 有功电能
			eeA.ActiveEnergy = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeB.ActiveEnergy = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeC.ActiveEnergy = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			// 无功电能
			eeA.ReactiveEnergy = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeB.ReactiveEnergy = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			eeC.ReactiveEnergy = gopsu.Bytes2Float32([]byte{d[j], d[j+1], d[j+2], d[j+3]}, false)
			j += 4
			svrmsg.WlstTml.WlstRtu_70A0.Ee = append(svrmsg.WlstTml.WlstRtu_70A0.Ee, eeA)
			svrmsg.WlstTml.WlstRtu_70A0.Ee = append(svrmsg.WlstTml.WlstRtu_70A0.Ee, eeB)
			svrmsg.WlstTml.WlstRtu_70A0.Ee = append(svrmsg.WlstTml.WlstRtu_70A0.Ee, eeC)
		case 2: // gps数据
			svrmsg.WlstTml.WlstRtu_70A0.Temperature = int32(gopsu.Bytes2Int64([]byte{d[j]}, false))
			j++
			svrmsg.WlstTml.WlstRtu_70A0.Humidity = int32(d[j])
			j++
			svrmsg.WlstTml.WlstRtu_70A0.MainVoltage = float64(d[j]) / 10.0
			j++
			svrmsg.WlstTml.WlstRtu_70A0.BatteryPower = int32(d[j])
			j++
			s := fmt.Sprintf("%08b", d[j])
			svrmsg.WlstTml.WlstRtu_70A0.Gpsargs = &msgctl.WlstRtu_70A0_GpsArgs{}
			svrmsg.WlstTml.WlstRtu_70A0.Gpsargs.LocationStatus = gopsu.String2Int32(string(s[0]), 10)
			svrmsg.WlstTml.WlstRtu_70A0.Gpsargs.LatType = gopsu.String2Int32(string(s[1]), 10)
			svrmsg.WlstTml.WlstRtu_70A0.Gpsargs.LonType = gopsu.String2Int32(string(s[2]), 10)
			svrmsg.WlstTml.WlstRtu_70A0.Gpsargs.GpsType = gopsu.String2Int32(string(s[6:]), 2)
			j++
			svrmsg.WlstTml.WlstRtu_70A0.Longitude = gopsu.Bytes2Float64([]byte{d[j], d[j+1], d[j+2], d[j+3], d[j+4], d[j+5], d[j+6], d[j+7]}, false)
			j += 8
			svrmsg.WlstTml.WlstRtu_70A0.Latitude = gopsu.Bytes2Float64([]byte{d[j], d[j+1], d[j+2], d[j+3], d[j+4], d[j+5], d[j+6], d[j+7]}, false)
			j += 8
		case 3: // 24路输出选测
			svrmsg.WlstTml.WlstRtu_70A0.LoopCount = int32(d[j])
			j++
			for i := int32(0); i < svrmsg.WlstTml.WlstRtu_70A0.LoopCount; i++ {
				ee := &msgctl.WlstRtu_70A0_ElectricEnergy{}
				ee.Voltage = float32(float64(d[j+1])*256.0+float64(d[j])) / 100.0
				j += 2
				ee.Current = float32(float64(d[j+1])*256.0+float64(d[j])) / 100.0
				j += 2
				ee.ActivePower = float32(d[j+1])*256 + float32(d[j])
				j += 2
				svrmsg.WlstTml.WlstRtu_70A0.Ee = append(svrmsg.WlstTml.WlstRtu_70A0.Ee, ee)
			}
			// 输入状态
			ss := gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b%08b%08b%08b%08b%08b", d[j+7], d[j+6], d[j+5], d[j+4], d[j+3], d[j+2], d[j+1], d[j]))
			j += 8
			for _, v := range ss {
				svrmsg.WlstTml.WlstRtu_70A0.SwitchInStPacked = append(svrmsg.WlstTml.WlstRtu_70A0.SwitchInStPacked, v-48)
			}
			// 输出状态
			//ss = gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b%08b%08b%08b%08b%08b", d[j+7], d[j+6], d[j+5], d[j+4], d[j+3], d[j+2], d[j+1], d[j]))
			ss = gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b", d[j+2], d[j+1], d[j]))
			j += 8
			for _, v := range ss {
				svrmsg.WlstTml.WlstRtu_70A0.SwitchOutStPacked = append(svrmsg.WlstTml.WlstRtu_70A0.SwitchOutStPacked, v-48)
			}
			// 运行状态
			ss = gopsu.ReverseString(fmt.Sprintf("%08b", d[j]))
			j++
			for _, v := range ss {
				svrmsg.WlstTml.WlstRtu_70A0.TmlStPacked = append(svrmsg.WlstTml.WlstRtu_70A0.TmlStPacked, gopsu.String2Int32(string(v), 10))
			}
			// 温度
			svrmsg.WlstTml.WlstRtu_70A0.Temperature = int32(gopsu.Bytes2Int64([]byte{d[j]}, false))
			j++
			// 湿度
			svrmsg.WlstTml.WlstRtu_70A0.Humidity = int32(d[j])
			j++
			// 电源电压
			svrmsg.WlstTml.WlstRtu_70A0.MainVoltage = float64(d[j]) / 10.0
			j++
			// 复位次数
			svrmsg.WlstTml.WlstRtu_70A0.TmlReset = append(svrmsg.WlstTml.WlstRtu_70A0.TmlReset, int32(d[j]), int32(d[j+1]), int32(d[j+2]), int32(d[j+3]))
			j += 4
		}
	case 0xf8: // 事件招测
		svrmsg.Head.Cmd = "wlst.rtu.f800"
		svrmsg.WlstTml.WlstRtuF800 = &msgctl.WlstRtu_7800{}
		svrmsg.WlstTml.WlstRtuF800.EventType = int32(d[5])
		svrmsg.WlstTml.WlstRtuF800.EventClass = int32(d[6])
		svrmsg.WlstTml.WlstRtuF800.AllNum = int32(d[7])
		svrmsg.WlstTml.WlstRtuF800.CurNum = int32(d[8])
		svrmsg.WlstTml.WlstRtuF800.RawData = gopsu.Bytes2String(d, "-")
		zm := svrmsg.WlstTml.WlstRtuF800
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0x85: // 3006招测版本
		svrmsg.Head.Cmd = "wlst.rtu.dc00"
		svrmsg.WlstTml.WlstRtuDc00 = &msgctl.WlstRtuDc00{}
		svrmsg.WlstTml.WlstRtuDc00.Ver = string(d[9 : 9+ll-7])

		zm := svrmsg.WlstTml.WlstRtuDc00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		ff := &Fwd{
			DataCmd:  f.DataCmd,
			DataType: DataTypeBase64,
			DataDst:  "6",
			DstType:  SockUpgrade,
			Tra:      TraDirect,
			Job:      JobSend,
			Src:      gopsu.Bytes2String(d, "-"),
			DataMsg:  CodePb2(svrmsg),
		}
		lstf = append(lstf, ff)
	case 0x90: // 复位应答
		svrmsg.WlstTml.WlstRtu_7090 = &msgctl.WlstRtu_7010{}
		svrmsg.WlstTml.WlstRtu_7090.CmdIdx = int32(d[7])
		switch ll {
		case 5:
			svrmsg.WlstTml.WlstRtu_7090.DataMark = int32(d[7])
			svrmsg.WlstTml.WlstRtu_7090.Status = int32(d[8])
		case 6:
			svrmsg.WlstTml.WlstRtu_7090.DataMark = int32(d[8])
			svrmsg.WlstTml.WlstRtu_7090.Status = int32(d[9])
		}
		zm := svrmsg.WlstTml.WlstRtu_7090
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xe0: // 设置年开关灯应答
		svrmsg.WlstTml.WlstRtu_70E0 = &msgctl.WlstRtu_70E0{}
		svrmsg.WlstTml.WlstRtu_70E0.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstRtu_70E0.Status = int32(d[8])
		zm := svrmsg.WlstTml.WlstRtu_70E0
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xe1: // 读取年设置
		svrmsg.WlstTml.WlstRtu_70E1 = &msgctl.WlstRtu_7060{}
		svrmsg.WlstTml.WlstRtu_70E1.CmdIdx = int32(d[7])
		t := time.Now()
		svrmsg.WlstTml.WlstRtu_70E1.DtStart = gopsu.Time2Stamp(fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", t.Year(), d[8], d[9], t.Hour(), t.Minute(), t.Second()))
		svrmsg.WlstTml.WlstRtu_70E1.Days = int32(d[10])
		m := fmt.Sprintf("%08b%08b", d[12], d[11])
		m = gopsu.ReverseString(m)
		j := 13
		for k, v := range m {
			if v == 48 {
				continue
			}
			yc := &msgctl.WlstRtu_7060_YearCtrl{}
			yc.LoopNo = int32(k + 1)
			yc.TimeCount = int32(d[j])
			j++
			for z := byte(0); z < d[10]; z++ {
				for y := int32(0); y < yc.TimeCount; y++ {
					yc.OptTime = append(yc.OptTime, int32(d[j])*60+int32(d[j+1]), int32(d[j+2])*60+int32(d[j+3]))
					j += 4
				}
			}
			svrmsg.WlstTml.WlstRtu_70E1.YearCtrl = append(svrmsg.WlstTml.WlstRtu_70E1.YearCtrl, yc)
		}
		zm := svrmsg.WlstTml.WlstRtu_70E1
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xd0: // 新版选测
		svrmsg.WlstTml.WlstRtu_70D0 = &msgctl.WlstRtu_70D0{}
		svrmsg.WlstTml.WlstRtu_70D0.DataMark = &msgctl.WlstRtu_70D0_DataMark{
			GetRunData:         0,
			GetSwitchoutReason: 0,
		}
		j := 7
		svrmsg.WlstTml.WlstRtu_70D0.CmdIdx = int32(d[j])
		j++
		m := fmt.Sprintf("%08b", d[j])
		j++
		var p, dp int
		var dc = make([]int, 0)
		for _, v := range m {
			if v == 49 {
				dc = append(dc, int(d[j+1])*256+int(d[j]))
				p++
				j += 2
			}
		}
		dp = 8 + p*2 + 1
		if m[7] == 49 {
			j = dp
			svrmsg.WlstTml.WlstRtu_70D0.DataMark.GetRunData = 1
			z := int(d[j])
			j++
			for i := 0; i < z; i++ {
				sv := &msgctl.WlstRtu_70D0_SamplingVoltage{}
				sv.VolA = (float64(d[j+1])*256.0 + float64(d[j])) / 100.0
				j += 2
				sv.VolB = (float64(d[j+1])*256.0 + float64(d[j])) / 100.0
				j += 2
				sv.VolC = (float64(d[j+1])*256.0 + float64(d[j])) / 100.0
				j += 2
				svrmsg.WlstTml.WlstRtu_70D0.SamplingVoltage = append(svrmsg.WlstTml.WlstRtu_70D0.SamplingVoltage, sv)
			}
			z = int(d[j])
			j++
			for i := 0; i < z; i++ {
				sv := &msgctl.WlstRtu_70D0_AnalogData{}
				sv.Voltage = (float64(d[j+1])*256 + float64(d[j])) / 100.0
				j += 2
				sv.Current = (float64(d[j+1])*256 + float64(d[j])) / 100.0
				j += 2
				sv.Power = float64(d[j+1])*256 + float64(d[j])
				j += 2
				svrmsg.WlstTml.WlstRtu_70D0.AnalogData = append(svrmsg.WlstTml.WlstRtu_70D0.AnalogData, sv)
			}
			ss := gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b%08b%08b%08b%08b", d[j+6], d[j+5], d[j+4], d[j+3], d[j+2], d[j+1], d[j]))
			for _, v := range ss {
				if v == 48 {
					svrmsg.WlstTml.WlstRtu_70D0.SwitchInStPacked = append(svrmsg.WlstTml.WlstRtu_70D0.SwitchInStPacked, 1)
				} else {
					svrmsg.WlstTml.WlstRtu_70D0.SwitchInStPacked = append(svrmsg.WlstTml.WlstRtu_70D0.SwitchInStPacked, 0)
				}
			}
			svrmsg.WlstTml.WlstRtu_70D0.SwitchInSt = gopsu.String2Int64(gopsu.ReverseString(ss), 2) ^ 0xffffffffffffff
			j += 7
			ss = gopsu.ReverseString(fmt.Sprintf("%08b", d[j]))
			for _, v := range ss {
				svrmsg.WlstTml.WlstRtu_70D0.SwitchOutStPacked = append(svrmsg.WlstTml.WlstRtu_70D0.SwitchOutStPacked, gopsu.String2Int32(string(v), 10))
			}
			svrmsg.WlstTml.WlstRtu_70D0.SwitchOutSt = gopsu.String2Int32(gopsu.ReverseString(ss), 2)
			j++
			ss = gopsu.ReverseString(fmt.Sprintf("%08b", d[j]))
			for _, v := range ss {
				svrmsg.WlstTml.WlstRtu_70D0.TmlStPacked = append(svrmsg.WlstTml.WlstRtu_70D0.TmlStPacked, gopsu.String2Int32(string(v), 10))
			}
			svrmsg.WlstTml.WlstRtu_70D0.TmlSt = gopsu.String2Int32(gopsu.ReverseString(ss), 2)
			j++
			svrmsg.WlstTml.WlstRtu_70D0.Temperature = int32(d[j])
			j++
			svrmsg.WlstTml.WlstRtu_70D0.GprsReset = int32(d[j])
			j++
			svrmsg.WlstTml.WlstRtu_70D0.GprsSignal = int32(d[j])
			j++
			svrmsg.WlstTml.WlstRtu_70D0.TmlReset = append(svrmsg.WlstTml.WlstRtu_70D0.TmlReset, int32(d[j]), int32(d[j+1]), int32(d[j+2]), int32(d[j+3]))
			j += 4
			ss = gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b", d[j+2], d[j+1], d[j]))
			for _, v := range ss {
				svrmsg.WlstTml.WlstRtu_70D0.TmlArgsStatus = append(svrmsg.WlstTml.WlstRtu_70D0.TmlArgsStatus, gopsu.String2Int32(string(v), 10))
			}
			j += 3
			svrmsg.WlstTml.WlstRtu_70D0.PowerSupply = float64(d[j]) / 10.0
			j++
		}
		if m[6] == 49 {
			svrmsg.WlstTml.WlstRtu_70D0.DataMark.GetSwitchoutReason = 1
			svrmsg.WlstTml.WlstRtu_70D0.SwitchOutReason = append(svrmsg.WlstTml.WlstRtu_70D0.SwitchOutReason, int32(d[j]), int32(d[j+1]), int32(d[j+2]), int32(d[j+3]), int32(d[j+4]), int32(d[j+5]), int32(d[j+6]), int32(d[j+7]))
			j += 8
		}
		zm := svrmsg.WlstTml.WlstRtu_70D0
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xda: // 新版招测参数
		svrmsg.WlstTml.WlstRtu_70Da = &msgctl.WlstRtu_70Da{}
		j := 7
		svrmsg.WlstTml.WlstRtu_70Da.CmdIdx = int32(d[j])
		j++
		svrmsg.WlstTml.WlstRtu_70Da.CmdType = int32(d[j])
		j++
		switch svrmsg.WlstTml.WlstRtu_70Da.CmdType {
		case 1: // 终端参数
			svrmsg.WlstTml.WlstRtu_70Da.KeepAlive = int32(d[j])
			j++
			svrmsg.WlstTml.WlstRtu_70Da.AlarmCycle = int32(d[j])
			j++
			svrmsg.WlstTml.WlstRtu_70Da.AlarmDelay = int32(d[j])
			j = j + 3
			svrmsg.WlstTml.WlstRtu_70Da.SwitchOutSum = int32(d[j])
			j++
			svrmsg.WlstTml.WlstRtu_70Da.SwitchInSum = int32(d[j])
			j++
			svrmsg.WlstTml.WlstRtu_70Da.AnalogSum = int32(d[j])
			j++
			for i := 0; i < 8; i++ {
				svrmsg.WlstTml.WlstRtu_70Da.XSwitchingTime = append(svrmsg.WlstTml.WlstRtu_70Da.XSwitchingTime, fmt.Sprintf("%02x%02x-%02x%02x", d[j], d[j+1], d[j+2], d[j+3]))
				j += 4
			}
			svrmsg.WlstTml.WlstRtu_70Da.CityPayTime = fmt.Sprintf("%02x%02x", d[j], d[j+1])
			j += 2
			svrmsg.WlstTml.WlstRtu_70Da.SelfPayTime = fmt.Sprintf("%02x%02x", d[j], d[j+1])
			j += 2
			svrmsg.WlstTml.WlstRtu_70Da.XSwitchOutCount = append(svrmsg.WlstTml.WlstRtu_70Da.XSwitchOutCount, int32(d[j]), int32(d[j+1]), int32(d[j+2]), int32(d[j+3]), int32(d[j+4]), int32(d[j+5]), int32(d[j+6]), int32(d[j+7]))
			j += 8
			s := gopsu.ReverseString(fmt.Sprintf("%08b%08b", d[j+1], d[j]))
			for _, v := range s {
				svrmsg.WlstTml.WlstRtu_70Da.SwitchInHopping = append(svrmsg.WlstTml.WlstRtu_70Da.SwitchInHopping, gopsu.String2Int32(string(v), 10))
			}
			j += 2
			svrmsg.WlstTml.WlstRtu_70Da.VoltageRange = int32(d[j]) * 5
			j++
			for i := 0; i < 48; i++ {
				svrmsg.WlstTml.WlstRtu_70Da.XCurrentRange = append(svrmsg.WlstTml.WlstRtu_70Da.XCurrentRange, int32(d[j])*5)
				j++
			}
			for i := 0; i < 8; i++ {
				svrmsg.WlstTml.WlstRtu_70Da.XSwitchOutVector = append(svrmsg.WlstTml.WlstRtu_70Da.XSwitchOutVector, int32(d[j])+1)
				j++
			}
			for i := 0; i < 56; i++ {
				svrmsg.WlstTml.WlstRtu_70Da.XSwitchInVector = append(svrmsg.WlstTml.WlstRtu_70Da.XSwitchInVector, int32(d[j])+1)
				j++
			}
			for i := 0; i < 48; i++ {
				svrmsg.WlstTml.WlstRtu_70Da.XAnalogVector = append(svrmsg.WlstTml.WlstRtu_70Da.XAnalogVector, int32(d[j])+1)
				j++
			}
			svrmsg.WlstTml.WlstRtu_70Da.LowerVoltageLimit = int32(float32(d[j])*1.0/0x3f) * svrmsg.WlstTml.WlstRtu_70Da.VoltageRange
			j++
			svrmsg.WlstTml.WlstRtu_70Da.UpperVoltageLimit = int32(float32(d[j])*1.0/0x3f) * svrmsg.WlstTml.WlstRtu_70Da.VoltageRange
			j++
			for i := 0; i < 48; i++ {
				svrmsg.WlstTml.WlstRtu_70Da.XLowerCurrentLimit = append(svrmsg.WlstTml.WlstRtu_70Da.XLowerCurrentLimit, int32(float32(d[j])*1.0/0x3f)*svrmsg.WlstTml.WlstRtu_70Da.XCurrentRange[i])
				svrmsg.WlstTml.WlstRtu_70Da.XUpperCurrentLimit = append(svrmsg.WlstTml.WlstRtu_70Da.XUpperCurrentLimit, int32(float32(d[j+1])*1.0/0x3f)*svrmsg.WlstTml.WlstRtu_70Da.XCurrentRange[i])
				j += 2
			}
		case 2: // 电能板互感比，上传时×5
			for i := 0; i < 3; i++ {
				svrmsg.WlstTml.WlstRtu_70Da.Transformers = append(svrmsg.WlstTml.WlstRtu_70Da.Transformers, int32(d[j])*5)
				j++
			}
		}
		zm := svrmsg.WlstTml.WlstRtu_70Da
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0x8b: // 远程读取主板通讯参数
		f.DataCmd = "wlst.com.0200"
		f.DataMsg = []byte(fmt.Sprintf("%d^ok", f.Addr))
		f.DataDst = "6"
		f.DstType = 6
	case 0x8a: // 远程设置主板通讯参数
		f.DataCmd = "wlst.com.0000"
		f.DataMsg = []byte(fmt.Sprintf("%d^%s", f.Addr, gopsu.Bytes2String(d, "-")))
		f.DataDst = "6"
		f.DstType = 6
	case 0x83: // ftp更新应答
		f.DataDst = "6"
		f.DstType = 6
		svrmsg.WlstTml.WlstRtu_7083 = &msgctl.WlstRtu_7087{}
		svrmsg.WlstTml.WlstRtu_7083.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstRtu_7083.Status = int32(d[8])
	case 0x84: // 上海路灯升级准备
	case 0x86, 0x87, 0x88: // 硬件升级
		return dataUpgrade(d, ip, portlocal, 0)
	case 0xd3: // 读取sd卡
		svrmsg.Head.Cmd = "wlst.rtu.70d3"
		svrmsg.WlstTml.WlstRtu_70D3 = &msgctl.WlstRtu_70D3{}
		svrmsg.WlstTml.WlstRtu_70D3.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstRtu_70D3.RecordType = int32(d[8])
		svrmsg.WlstTml.WlstRtu_70D3.DtStart = gopsu.Time2Stamp(fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", int(d[9])+int(d[10])*256, d[11], d[12], d[13], d[14], d[15]))
		svrmsg.WlstTml.WlstRtu_70D3.RecordTotal = int32(d[16])
		svrmsg.WlstTml.WlstRtu_70D3.RecordDistance = int64(d[17]) + int64(d[18])*256 + int64(d[19])*256*256 + int64(d[20])*256*256*256
		svrmsg.WlstTml.WlstRtu_70D3.RecordCount = int32(d[21])
		svrmsg.WlstTml.WlstRtu_70D3.RecordIdx = int32(d[22])
		svrmsg.WlstTml.WlstRtu_70D3.RecordStatus = int32(d[23])
		if svrmsg.WlstTml.WlstRtu_70D3.RecordTotal > 0 {
			j := 24
			switch svrmsg.WlstTml.WlstRtu_70D3.RecordType {
			case 1: // 选测数据
				for i := int32(0); i < svrmsg.WlstTml.WlstRtu_70D3.RecordTotal; i++ {
					if j >= len(d)-2 {
						break
					}
					d070 := &msgctl.WlstRtu_70D0{}
					d070.DataMark = &msgctl.WlstRtu_70D0_DataMark{}
					d070.DataMark.GetRunData = 1
					d070.DtRecord = gopsu.Time2Stamp(fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", int(d[j])+int(d[j+1])*256, d[j+2], d[j+3], d[j+4], d[j+5], d[j+6]))
					j += 7
					j++
					loopcount := d[j]
					j++
					for i := byte(0); i < loopcount; i++ {
						sv := &msgctl.WlstRtu_70D0_AnalogData{}
						sv.Voltage = (float64(d[j+1])*256 + float64(d[j])) / 100.0
						j += 2
						sv.Current = (float64(d[j+1])*256 + float64(d[j])) / 100.0
						j += 2
						sv.Power = float64(d[j+1])*256 + float64(d[j])
						j += 2
						d070.AnalogData = append(d070.AnalogData, sv)
					}
					ss := gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b%08b%08b%08b%08b", d[j+6], d[j+5], d[j+4], d[j+3], d[j+2], d[j+1], d[j]))
					j += 7
					for _, v := range ss {
						if v == 48 {
							d070.SwitchInStPacked = append(d070.SwitchInStPacked, 1)
						} else {
							d070.SwitchInStPacked = append(d070.SwitchInStPacked, 0)
						}
					}
					d070.SwitchInSt = gopsu.String2Int64(gopsu.ReverseString(ss), 2) ^ 0xffffffffffffff
					ss = gopsu.ReverseString(fmt.Sprintf("%08b", d[j]))
					for _, v := range ss {
						d070.SwitchOutStPacked = append(d070.SwitchOutStPacked, gopsu.String2Int32(string(v), 10))
					}
					d070.SwitchOutSt = gopsu.String2Int32(gopsu.ReverseString(ss), 2)
					j++
					ss = gopsu.ReverseString(fmt.Sprintf("%08b", d[j]))
					for _, v := range ss {
						d070.TmlStPacked = append(d070.TmlStPacked, gopsu.String2Int32(string(v), 10))
					}
					j++
					d070.TmlSt = gopsu.String2Int32(gopsu.ReverseString(ss), 2)
					svrmsg.WlstTml.WlstRtu_70D3.Data_70D0 = append(svrmsg.WlstTml.WlstRtu_70D3.Data_70D0, d070)
				}
			case 2: // 最大电流
				for i := int32(0); i < svrmsg.WlstTml.WlstRtu_70D3.RecordTotal; i++ {
					if j >= len(d)-2 {
						break
					}
					d070 := &msgctl.WlstRtu_70D0Max{}
					d070.DtRecord = gopsu.Time2Stamp(fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", int(d[j])+int(d[j+1])*256, d[j+2], d[j+3], d[j+4], d[j+5], d[j+6]))
					j += 7
					d070.RecordType = int32(d[j])
					j++
					d070.LoopCount = int32(d[j])
					j++
					y, m, dd, _, _, _, _ := gopsu.SplitDateTime(d070.DtRecord)
					for k := int32(0); k < d070.LoopCount; k++ {
						d070max := &msgctl.WlstRtu_70D0Max_MaxData{}
						d070max.CurrentMax = (float64(d[j]) + float64(d[j+1])*256.0) / 100.0
						j += 2
						d070max.DtRecord = gopsu.Time2Stamp(fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", y, m, dd, d[j], d[j+1], d[j+2]))
						j += 3
						d070.MaxData = append(d070.MaxData, d070max)
					}
					svrmsg.WlstTml.WlstRtu_70D3.Data_70D0Max = append(svrmsg.WlstTml.WlstRtu_70D3.Data_70D0Max, d070)
				}
			}
		}

		zm := svrmsg.WlstTml.WlstRtu_70D3
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0x94: // 终端主报
		svrmsg.WlstTml.WlstRtu_7094 = &msgctl.WlstRtu_7094{}
		svrmsg.WlstTml.WlstRtu_7094.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstRtu_7094.AlarmType = int32(d[8]) + 256*int32(d[9])
		switch svrmsg.WlstTml.WlstRtu_7094.AlarmType {
		case 400: // 漏电主报
			alarmln := &msgctl.WlstRtu_7094_Alarm_LN{}
			alarmln.LoopNo = int32(d[10]) + 1
			alarmln.AlarmStatus = int32(d[11])
			alarmln.AlarmCurrent = float64(gopsu.Bytes2Float32([]byte{d[12], d[13], d[14], d[15]}, false))
			svrmsg.WlstTml.WlstRtu_7094.Alarmln = alarmln
		case 401: // 24路开关灯结果
			ss := gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b", d[12], d[11], d[10]))
			for _, v := range ss {
				svrmsg.WlstTml.WlstRtu_7094.SwitchOutStPacked = append(svrmsg.WlstTml.WlstRtu_7094.SwitchOutStPacked, v-48)
			}
		}
		zm := svrmsg.WlstTml.WlstRtu_7094
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		sendstr := DoCommand(1, 1, 1, f.Addr, 1, "wlst.rtu.7014", []byte{d[7], d[8], d[9], d[10]}, 1, 1)

		ff := &Fwd{
			Addr:     f.Addr,
			DataCmd:  "wlst.rtu.7014",
			DataType: DataTypeBytes,
			DataPT:   1000,
			DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
			DstType:  SockTml,
			Tra:      TraDirect,
			Job:      JobSend,
			DataMsg:  sendstr,
		}
		lstf = append(lstf, ff)

		ff = &Fwd{
			Addr:     f.Addr,
			DataCmd:  "wlst.rtu.2000",
			DataType: DataTypeBytes,
			DataPT:   1000,
			DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
			DstType:  SockTml,
			Tra:      TraDirect,
			Job:      JobSend,
			DataMsg:  Send2000,
		}
		lstf = append(lstf, ff)
	case 0xa1: // 设置终端参数应答（火零不平衡检测，24路周设置）
		svrmsg.WlstTml.WlstRtu_70A1 = &msgctl.WlstRtu_7021{}
		svrmsg.WlstTml.WlstRtu_70A1.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstRtu_70A1.DataType = int32(d[8])
		svrmsg.WlstTml.WlstRtu_70A1.LoopType = int32(d[9])
		svrmsg.WlstTml.WlstRtu_70A1.StatusCode = int32(d[10])
		zm := svrmsg.WlstTml.WlstRtu_70A1
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xa2: // 招测终端参数应答（火零不平衡检测，24路周设置）
		svrmsg.WlstTml.WlstRtu_70A2 = &msgctl.WlstRtu_7021{}
		svrmsg.WlstTml.WlstRtu_70A2.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstRtu_70A2.DataType = int32(d[8])
		switch svrmsg.WlstTml.WlstRtu_70A2.DataType {
		case 1:
			ss := gopsu.ReverseString(fmt.Sprintf("%08b%08b", d[10], d[9]))
			loopNo := make([]int32, 16)
			for k, v := range ss {
				loopNo[k] = v - 48 // gopsu.String2Int32(string(v), 10)
			}
			for i := 0; i < 12; i++ {
				if loopNo[i] == 1 {
					argsln := &msgctl.WlstRtu_7021_Args_LN{}
					argsln.LoopNo = int32(i + 1)
					argsln.BaseValue = int32(d[11+i])
					argsln.AlarmValue = int32(d[23+i])
					argsln.BreakValue = int32(d[35+i])
					svrmsg.WlstTml.WlstRtu_70A2.Argsln = append(svrmsg.WlstTml.WlstRtu_70A2.Argsln, argsln)
				}
			}
			zm := svrmsg.WlstTml.WlstRtu_70A2
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				f.DataMQ = b
			}
		case 2:
			svrmsg.WlstTml.WlstRtu_70A2.LoopType = int32(d[9])
			for i := 0; i < 7; i++ {
				argswc := &msgctl.WlstRtu_7021_Args_WC{}
				argswc.L1On = int32(gopsu.Bcd2Int8(d[i*32+10]))*60 + int32(gopsu.Bcd2Int8(d[i*32+11]))
				argswc.L1Off = int32(gopsu.Bcd2Int8(d[i*32+12]))*60 + int32(gopsu.Bcd2Int8(d[i*32+13]))
				argswc.L2On = int32(gopsu.Bcd2Int8(d[i*32+14]))*60 + int32(gopsu.Bcd2Int8(d[i*32+15]))
				argswc.L2Off = int32(gopsu.Bcd2Int8(d[i*32+16]))*60 + int32(gopsu.Bcd2Int8(d[i*32+17]))
				argswc.L3On = int32(gopsu.Bcd2Int8(d[i*32+18]))*60 + int32(gopsu.Bcd2Int8(d[i*32+19]))
				argswc.L3Off = int32(gopsu.Bcd2Int8(d[i*32+20]))*60 + int32(gopsu.Bcd2Int8(d[i*32+21]))
				argswc.L4On = int32(gopsu.Bcd2Int8(d[i*32+22]))*60 + int32(gopsu.Bcd2Int8(d[i*32+23]))
				argswc.L4Off = int32(gopsu.Bcd2Int8(d[i*32+24]))*60 + int32(gopsu.Bcd2Int8(d[i*32+25]))
				argswc.L5On = int32(gopsu.Bcd2Int8(d[i*32+26]))*60 + int32(gopsu.Bcd2Int8(d[i*32+27]))
				argswc.L5Off = int32(gopsu.Bcd2Int8(d[i*32+28]))*60 + int32(gopsu.Bcd2Int8(d[i*32+29]))
				argswc.L6On = int32(gopsu.Bcd2Int8(d[i*32+30]))*60 + int32(gopsu.Bcd2Int8(d[i*32+31]))
				argswc.L6Off = int32(gopsu.Bcd2Int8(d[i*32+32]))*60 + int32(gopsu.Bcd2Int8(d[i*32+33]))
				argswc.L7On = int32(gopsu.Bcd2Int8(d[i*32+34]))*60 + int32(gopsu.Bcd2Int8(d[i*32+35]))
				argswc.L7Off = int32(gopsu.Bcd2Int8(d[i*32+36]))*60 + int32(gopsu.Bcd2Int8(d[i*32+37]))
				argswc.L8On = int32(gopsu.Bcd2Int8(d[i*32+38]))*60 + int32(gopsu.Bcd2Int8(d[i*32+39]))
				argswc.L8Off = int32(gopsu.Bcd2Int8(d[i*32+40]))*60 + int32(gopsu.Bcd2Int8(d[i*32+41]))
				svrmsg.WlstTml.WlstRtu_70A2.Argswc = append(svrmsg.WlstTml.WlstRtu_70A2.Argswc, argswc)
			}
			cmdidx := svrmsg.WlstTml.WlstRtu_70A2.CmdIdx + 1
			if cmdidx > 255 {
				cmdidx = 0
			}
			if svrmsg.WlstTml.WlstRtu_70A2.LoopType < 2 {
				ff := &Fwd{
					Addr:     f.Addr,
					DataCmd:  "wlst.rtu.7022",
					DataType: DataTypeBytes,
					DataPT:   3000,
					DataDst:  fmt.Sprintf("wlst-rtu-%d", f.Addr),
					DstType:  1,
					Tra:      TraDirect,
					Job:      JobSend,
					DataMsg:  DoCommand(1, 1, TraDirect, f.Addr, svrmsg.Args.Cid, "wlst.rtu.7022", []byte{byte(cmdidx), 0x02, byte(svrmsg.WlstTml.WlstRtu_70A2.LoopType + 1)}, 5, 0),
				}
				lstf = append(lstf, ff)
			}
			zm := svrmsg.WlstTml.WlstRtu_70A2
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				f.DataMQ = b
			}
		}
	case 0xa3: // 24路遥控开关灯应答 武汉亮化
		svrmsg.WlstTml.WlstRtu_70A3 = &msgctl.WlstRtu_7023{}
		svrmsg.WlstTml.WlstRtu_70A3.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstRtu_70A3.DataType = int32(d[8])
		svrmsg.WlstTml.WlstRtu_70A3.StatusCode = int32(d[9])
		zm := svrmsg.WlstTml.WlstRtu_70A3
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	default:
		f.Ex = fmt.Sprintf("Unhandled rtu protocol: %s", gopsu.Bytes2String(d, "-"))
		lstf = append(lstf, f)
		return lstf
	}

	if len(f.DataCmd) > 0 {
		f.DataCmd = svrmsg.Head.Cmd
		f.DataMsg = CodePb2(svrmsg)
		lstf = append(lstf, f)
	}

	return lstf
}

// 处理防盗数据
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
//  tra：是否485数据1-非485,2-485
//  tmladdr: 为485数据时，父设备物理地址
// Return:
// 	lstf: 处理反馈结果
func dataLdu(d []byte, ip *int64, tra byte, tmladdr int64, portlocal *int) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      tra,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}
	if !gopsu.CheckCrc16VB(d) {
		f.Ex = fmt.Sprintf("Ldu data validation fails")
		lstf = append(lstf, f)
		return lstf
	}
	var cmd, cid int32
	cmd = int32(d[4])
	if tmladdr == 0 {
		f.Addr = int64(d[3])*256 + int64(d[2])
		cid = 1
	} else {
		f.Addr = tmladdr
		cid = int32(d[3])*256 + int32(d[2])
	}
	svrmsg := initMsgCtl(fmt.Sprintf("wlst.ldu.%02x00", cmd), f.Addr, *ip, 1, tra, cid, portlocal)
	f.DataCmd = svrmsg.Head.Cmd
	switch cmd {
	case 0xdc: // 招测版本
		s := string(d[5 : 5+20])
		if strings.Contains(s, "3090") {
			svrmsg.WlstTml.WlstLduDc00 = &msgctl.WlstRtuDc00{}
			svrmsg.WlstTml.WlstLduDc00.Ver = s
			zm := svrmsg.WlstTml.WlstLduDc00
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				f.DataMQ = b
			}
		} else {
			svrmsg.WlstTml.WlstRtuDc00 = &msgctl.WlstRtuDc00{}
			svrmsg.Head.Cmd = "wlst.rtu.dc00"
			f.DataCmd = "wlst.rtu.dc00"
			svrmsg.WlstTml.WlstRtuDc00.Ver = s
			zm := svrmsg.WlstTml.WlstRtuDc00
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				f.DataMQ = b
			}
			ff := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeBase64,
				DataDst:  "6",
				DstType:  SockUpgrade,
				Tra:      tra,
				Job:      JobSend,
				Src:      gopsu.Bytes2String(d, "-"),
				DataMsg:  CodePb2(svrmsg),
			}
			lstf = append(lstf, ff)
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.ver", s)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xa6: // 选测
		svrmsg.WlstTml.WlstLduA600 = &msgctl.WlstLduA600{}
		svrmsg.WlstTml.WlstLduA600.LoopMark = int32(d[5])
		m := fmt.Sprintf("%08b", d[5])
		l := d[1] - 6
		i := 0
		if l%16 == 0 {
			for j := 7; j > 0; j-- {
				if m[j] == 49 {
					ld := &msgctl.WlstLduA600_LduLoopData{}
					ld.XVoltage = (float64(d[16*i+1+1+4]) + float64(d[16*i+2+1+4])*256.0) / 100.0
					ld.XCurrent = (float64(d[16*i+3+1+4]) + float64(d[16*i+4+1+4])*256.0) / 100.0
					ld.XActivePower = (float64(d[16*i+5+1+4]) + float64(d[16*i+6+1+4])*256.0) / 100.0
					ld.XReactivePower = (float64(d[16*i+7+1+4]) + float64(d[16*i+8+1+4])*256.0) / 100.0
					ld.XPowerFactor = float64(d[16*i+9+1+4]) / 100.0
					ld.XLightingRate = float64(d[16*i+10+1+4])
					ld.XSignalStrength = int32(d[16*i+11+1+4]) * 10
					ld.XImpedance = int32(d[16*i+12+1+4]) * 10
					ld.XUsefulSignal = int32(d[16*i+13+1+4])
					ld.XAllSignal = int32(d[16*i+14+1+4])
					ld.XDetectionFlag = int32(d[16*i+15+1+4])
					ld.XAlarmFlag = int32(d[16*i+16+1+4])
					svrmsg.WlstTml.WlstLduA600.LduLoopData = append(svrmsg.WlstTml.WlstLduA600.LduLoopData, ld)
					i++
				}
			}
		}
		if l%19 == 0 {
			for j := 7; j > 0; j-- {
				if m[j] == 49 {
					ld := &msgctl.WlstLduA600_LduLoopData{}
					ld.XVoltage = (float64(d[19*i+1+1+4]) + float64(d[19*i+2+1+4])*256.0) / 100.0
					ld.XCurrent = (float64(d[19*i+3+1+4]) + float64(d[19*i+4+1+4])*256.0) / 100.0
					ld.XActivePower = (float64(d[19*i+5+1+4]) + float64(d[19*i+6+1+4])*256.0) / 100.0
					ld.XReactivePower = (float64(d[19*i+7+1+4]) + float64(d[19*i+8+1+4])*256.0) / 100.0
					ld.XPowerFactor = float64(d[19*i+9+1+4]) / 100.0
					ld.XLightingRate = float64(d[19*i+10+1+4])
					ld.XSignalStrength = int32(d[19*i+11+1+4]) * 10
					ld.XImpedance = int32(d[19*i+12+1+4]) + int32(d[19*i+13+1+4])*256
					ld.XUsefulSignal = int32(d[19*i+14+1+4])
					ld.XAllSignal = int32(d[19*i+15+1+4])
					ld.XDetectionFlag = int32(d[19*i+16+1+4])
					ld.XAlarmFlag = int32(d[19*i+17+1+4])
					svrmsg.WlstTml.WlstLduA600.LduLoopData = append(svrmsg.WlstTml.WlstLduA600.LduLoopData, ld)
					i++
				}
			}
		}
		zm := svrmsg.WlstTml.WlstLduA600
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}

		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.ln", svrmsg.WlstTml.WlstLduA600.LoopMark)
			i = 0
			if l%16 == 0 {
				for j := 7; j > 1; j-- {
					if m[j] == 49 {
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dv", 8-j), (float64(d[16*i+1+1+4])+float64(d[16*i+2+1+4])*256.0)/100.0)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%da", 8-j), (float64(d[16*i+3+1+4])+float64(d[16*i+4+1+4])*256.0)/100.0)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dnp", 8-j), (float64(d[16*i+5+1+4])+float64(d[16*i+6+1+4])*256.0)/100.0)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dp", 8-j), (float64(d[16*i+7+1+4])+float64(d[16*i+8+1+4])*256.0)/100.0)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dc", 8-j), float64(d[16*i+9+1+4])/100.0)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dr", 8-j), float64(d[16*i+10+1+4]))
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dss", 8-j), int32(d[16*i+11+1+4])*10)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%di", 8-j), int32(d[16*i+12+1+4])+int32(d[16*i+13+1+4])*256)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dus", 8-j), int32(d[16*i+14+1+4]))
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dsc", 8-j), int32(d[16*i+15+1+4]))
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dcv", 8-j), int32(d[16*i+16+1+4]))
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dav", 8-j), int32(d[16*i+17+1+4]))
						i++
					}
				}
			}
			if l%19 == 0 {
				for j := 7; j > 1; j-- {
					if m[j] == 49 {
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dv", 8-j), (float64(d[19*i+1+1+4])+float64(d[19*i+2+1+4])*256.0)/100.0)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%da", 8-j), (float64(d[19*i+3+1+4])+float64(d[19*i+4+1+4])*256.0)/100.0)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dnp", 8-j), (float64(d[19*i+5+1+4])+float64(d[19*i+6+1+4])*256.0)/100.0)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dp", 8-j), (float64(d[19*i+7+1+4])+float64(d[19*i+8+1+4])*256.0)/100.0)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dc", 8-j), float64(d[19*i+9+1+4])/100.0)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dr", 8-j), float64(d[19*i+10+1+4]))
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dss", 8-j), int32(d[19*i+11+1+4])*10)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%di", 8-j), int32(d[19*i+12+1+4])+int32(d[19*i+13+1+4])*256)
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dus", 8-j), int32(d[19*i+14+1+4]))
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dsc", 8-j), int32(d[19*i+15+1+4]))
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dcv", 8-j), int32(d[19*i+16+1+4]))
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dav", 8-j), int32(d[19*i+17+1+4]))
						i++
					}
				}
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xdb: // 读取参数
		svrmsg.WlstTml.WlstLduDb00 = &msgctl.WlstLdu_4900{}
		m := fmt.Sprintf("%08b", d[5])
		svrmsg.WlstTml.WlstLduDb00.LoopMark = int32(d[5])
		k := 0
		for i := 7; i > 1; i-- {
			if m[i] == 49 {
				ld := &msgctl.WlstLdu_4900_LduLoopArgv{}
				ld.XDetectionFlag = int32(d[k*10+1+1+4])
				ld.XTransformer = int32(d[k*10+2+1+4]) * 5
				ld.XPhase = int32(d[k*10+3+1+4])
				ld.XOnSignalStrength = int32(d[k*10+4+1+4]) * 10
				ld.XOnImpedanceAlarm = int32(d[k*10+5+1+4]) * 10
				ld.XLightingRate = int32(d[k*10+6+1+4])
				ld.XOffSignalStrength = int32(d[k*10+7+1+4]) * 10
				ld.XOffImpedanceAlarm = int32(d[k*10+8+1+4]) * 10
				ld.XPoleNo = int32(d[k*10+9+1+4]) + int32(d[k*10+10+1+4])*256
				svrmsg.WlstTml.WlstLduDb00.LduLoopArgv = append(svrmsg.WlstTml.WlstLduDb00.LduLoopArgv, ld)
				k++
			}
		}
		zm := svrmsg.WlstTml.WlstLduDb00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}

		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.ln", svrmsg.WlstTml.WlstLduDb00.LoopMark)
			k = 0
			for i := 7; i > 1; i-- {
				if m[i] == 49 {
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dcv", 8-i), int32(d[k*10+1+1+4]))
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dt", 8-i), int32(d[k*10+2+1+4])*5)
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dph", 8-i), int32(d[k*10+3+1+4]))
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dos", 8-i), int32(d[k*10+4+1+4])*10)
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%doi", 8-i), int32(d[k*10+5+1+4])*10)
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dlr", 8-i), int32(d[k*10+6+1+4]))
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dcs", 8-i), int32(d[k*10+7+1+4])*10)
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dci", 8-i), int32(d[k*10+8+1+4])*10)
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dex", 8-i), int32(d[k*10+9+1+4])+int32(d[k*10+10+1+4])*256)
					k++
				}
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xcd: // 选测检测终端状态(0x01->选测开灯阻抗基准，0x02->选测开灯阻抗最大值，0x03->复位开灯阻抗最大值)
		switch d[5] {
		case 1:
			s := fmt.Sprintf("%08b", d[5])
			svrmsg.Head.Cmd = "wlst.ldu.cd01"
			svrmsg.WlstTml.WlstLduCd01 = &msgctl.WlstLduCd01{}
			svrmsg.WlstTml.WlstLduCd01.LoopMark = int32(d[5])
			k := 0
			for j := 7; j > 1; j-- {
				if s[j] == 49 {
					svrmsg.WlstTml.WlstLduCd01.XImpedance = append(svrmsg.WlstTml.WlstLduCd01.XImpedance,
						int32(float64(d[k*4+2+1+4])/1000+
							float64(d[k*4+3+1+4])*0.256+
							float64(d[k*4+4+1+4])*256.0*0.256+
							float64(d[k*4+5+1+4])*256*256*0.256))
					k++
				}
			}

			zm := svrmsg.WlstTml.WlstLduCd01
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				f.DataMQ = b
			}
			if AnsJSON {
				jv, _ := sjson.Set(JSONData, "head.cmd", svrmsg.Head.Cmd)
				jv, _ = sjson.Set(jv, "head.tra", tra)
				jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
				jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
				jv, _ = sjson.Set(jv, "args.port", *portlocal)
				jv, _ = sjson.Set(jv, "data.ln", svrmsg.WlstTml.WlstLduCd01.LoopMark)
				k = 0
				for i := 7; i > 1; i-- {
					if s[i] == 49 {
						jv, _ = sjson.Set(jv, fmt.Sprintf("data.l%dir", 8-i), int32(float64(d[k*4+2+1+4])/1000+float64(d[k*4+3+1+4])*0.256+float64(d[k*4+4+1+4])*256.0*0.256+float64(d[k*4+5+1+4])*256*256*0.256))
						k++
					}
				}
				ffj := &Fwd{
					DataCmd:  svrmsg.Head.Cmd,
					DataType: DataTypeString,
					DataDst:  "2",
					DstType:  SockData,
					Tra:      tra,
					Job:      JobSend,
					DataMsg:  []byte(jv),
				}
				lstf = append(lstf, ffj)
			}
		case 2:
			svrmsg.Head.Cmd = "wlst.ldu.cd02"
			zm := svrmsg.Head
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				f.DataMQ = b
			}
			if AnsJSON {
				jv, _ := sjson.Set(JSONData, "head.cmd", svrmsg.Head.Cmd)
				jv, _ = sjson.Set(jv, "head.tra", tra)
				jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
				jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
				jv, _ = sjson.Set(jv, "args.port", *portlocal)
				ffj := &Fwd{
					DataCmd:  svrmsg.Head.Cmd,
					DataType: DataTypeString,
					DataDst:  "2",
					DstType:  SockData,
					Tra:      tra,
					Job:      JobSend,
					DataMsg:  []byte(jv),
				}
				lstf = append(lstf, ffj)
			}
		}
	case 0x96: // 复位
		zm := svrmsg.Head
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xca: // 设置亮灯率
		if d[5] == 1 {
			svrmsg.Head.Cmd = "wlst.ldu.ca01"
			svrmsg.WlstTml.WlstLduCa01 = &msgctl.WlstLdu_2600{}
			svrmsg.WlstTml.WlstLduCa01.LoopMark = int32(d[6])
			zm := svrmsg.WlstTml.WlstLduCa01
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				f.DataMQ = b
			}
			if AnsJSON {
				jv, _ := sjson.Set(JSONData, "head.cmd", svrmsg.Head.Cmd)
				jv, _ = sjson.Set(jv, "head.tra", tra)
				jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
				jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
				jv, _ = sjson.Set(jv, "args.port", *portlocal)
				jv, _ = sjson.Set(jv, "data.ln", svrmsg.WlstTml.WlstLduCa01.LoopMark)
				ffj := &Fwd{
					DataCmd:  svrmsg.Head.Cmd,
					DataType: DataTypeString,
					DataDst:  "2",
					DstType:  SockData,
					Tra:      tra,
					Job:      JobSend,
					DataMsg:  []byte(jv),
				}
				lstf = append(lstf, ffj)
			}
		}
	case 0xc9: // 设置终端检测参数
		svrmsg.WlstTml.WlstLduC900 = &msgctl.WlstLdu_2600{}
		svrmsg.WlstTml.WlstLduC900.LoopMark = int32(d[5])
		zm := svrmsg.WlstTml.WlstLduC900
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.ln", svrmsg.WlstTml.WlstLduC900.LoopMark)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	default:
		f.Ex = fmt.Sprintf("Unhandled ldu protocol: %s", gopsu.Bytes2String(d, "-"))
		lstf = append(lstf, f)
		return lstf
	}
	if len(f.DataCmd) > 0 {
		f.DataCmd = svrmsg.Head.Cmd
		f.DataMsg = CodePb2(svrmsg)
		lstf = append(lstf, f)
	}

	return lstf
}

// 处理单灯数据
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
//  tra：是否485数据1-非485,2-485
//  tmladdr: 为485数据时，父设备物理地址
// Return:
// 	lstf: 处理反馈结果
func dataSlu(d []byte, ip *int64, tra byte, tmladdr int64, portlocal *int) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      tra,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}
	if !gopsu.CheckCrc16VB(d) {
		f.Ex = fmt.Sprintf("Slu data validation fails")
		lstf = append(lstf, f)
		return lstf
	}
	var cid, cmd int32
	if d[6] != 0xfd {
		cmd = int32(d[6])
	} else {
		cmd = 0xf4
	}
	if tmladdr > 0 {
		tra = 2
		f.Addr = tmladdr
		cid = int32(d[4]) + int32(d[5])*256
	} else {
		tra = 1
		cid = 1
		f.Addr = int64(d[4]) + int64(d[5])*256
	}
	ll := int32(d[3])*256 + int32(d[2])
	svrmsg := initMsgCtl(fmt.Sprintf("wlst.slu.%02x00", cmd), f.Addr, *ip, 1, tra, cid, portlocal)
	f.DataCmd = svrmsg.Head.Cmd
	switch cmd {
	case 0xeb:
		svrmsg.WlstTml.WlstSluEb00 = &msgctl.WlstSluF400{}
		svrmsg.WlstTml.WlstSluEb00.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstSluEb00.Status = int32(d[8])
		zm := svrmsg.WlstTml.WlstSluEb00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0x9c:
		svrmsg.WlstTml.WlstSlu_9C00 = &msgctl.WlstSluF400{}
		svrmsg.WlstTml.WlstSlu_9C00.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstSlu_9C00.Status = int32(d[8])
		svrmsg.WlstTml.WlstSlu_9C00.Remark = int32(d[9])
		zm := svrmsg.WlstTml.WlstSlu_9C00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xf4, 0xfd:
		svrmsg.Head.Cmd = "wlst.slu.f400"
		svrmsg.WlstTml.WlstSluF400 = &msgctl.WlstSluF400{}
		svrmsg.WlstTml.WlstSluF400.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstSluF400.Status = int32(d[8])
		svrmsg.WlstTml.WlstSluF400.Remark = int32(d[9])
		zm := svrmsg.WlstTml.WlstSluF400
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xf6:
		svrmsg.WlstTml.WlstSluF600 = &msgctl.WlstSluF400{}
		svrmsg.WlstTml.WlstSluF600.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstSluF600.Status = int32(d[8])
		svrmsg.WlstTml.WlstSluF600.Remark = int32(d[9])
		zm := svrmsg.WlstTml.WlstSluF600
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xfc:
		svrmsg.WlstTml.WlstSluFc00 = &msgctl.WlstSluF400{}
		svrmsg.WlstTml.WlstSluFc00.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstSluFc00.Status = int32(d[8])
		if ll == 6 {
			f.Ex = "slu data length error"
		}
		svrmsg.WlstTml.WlstSluFc00.Remark = int32(d[9]) + int32(d[10])*256
		svrmsg.WlstTml.WlstSluFc00.SluitemAddr = int32(d[9]) + int32(d[10])*256
		zm := svrmsg.WlstTml.WlstSluFc00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xec: // 招测节假日设置
		svrmsg.WlstTml.WlstSluEc00 = &msgctl.WlstSluEc00{}
		svrmsg.WlstTml.WlstSluEc00.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstSluEc00.StartIdx = int32(d[8])
		svrmsg.WlstTml.WlstSluEc00.ReadCount = int32(d[9])
		j := 10
		for i := int32(0); i < int32(d[9]); i++ {
			d6b := &msgctl.WlstSlu_6B00{}
			d6b.SetIdx = int32(d[8]) + i
			d6b.DtStart = gopsu.Time2Stamp(fmt.Sprintf("%04d-%02d-%02d %02d:00:00", time.Now().Year(), d[j], d[j+1], d[j+2]))
			j += 3
			d6b.DtEnd = gopsu.Time2Stamp(fmt.Sprintf("%04d-%02d-%02d %02d:00:00", time.Now().Year(), d[j], d[j+1], d[j+2]))
			j += 3
			s := fmt.Sprintf("%08b", d[j])
			d6b.OperationOrder = gopsu.String2Int32(s[:4], 2)
			d6b.OperationType = gopsu.String2Int32(s[4:], 2)
			j++
			d6b.TimerOrOffset = int32(d[j])*60 + int32(d[j+1])
			j += 2
			d6b.CmdType = int32(d[j])
			j++
			switch d6b.CmdType {
			case 4:
				for k := 0; k < 4; k++ {
					switch d[j] {
					case 0:
						d6b.CmdMix = append(d6b.CmdMix, 0)
					case 0x33:
						d6b.CmdMix = append(d6b.CmdMix, 1)
					case 0x55:
						d6b.CmdMix = append(d6b.CmdMix, 2)
					case 0xaa:
						d6b.CmdMix = append(d6b.CmdMix, 3)
					case 0xcc:
						d6b.CmdMix = append(d6b.CmdMix, 4)
					}
					j++
				}
			case 5:
				s := fmt.Sprintf("%08b", d[j])
				j++
				d6b.CmdPwm = &msgctl.WlstSlu_6B00_CmdPwm{}
				for k := 7; k > 3; k-- {
					if s[k] == 48 {
						d6b.CmdPwm.LoopCanDo = append(d6b.CmdPwm.LoopCanDo, int32(8-k))
					}
				}
				d6b.CmdPwm.Scale = int32(d[j])
				j++
				d6b.CmdPwm.Rate = int32(d[j]) * 100
				j++
			}
			svrmsg.WlstTml.WlstSluEc00.WlstSlu_6B00 = append(svrmsg.WlstTml.WlstSluEc00.WlstSlu_6B00, d6b)
		}
		zm := svrmsg.WlstTml.WlstSlu_6B00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xd0: // 招测集中器版本
		svrmsg.WlstTml.WlstSluD000 = &msgctl.WlstSluD000{}
		svrmsg.WlstTml.WlstSluD000.Ver = string(d[7 : ll-5+7])
		zm := svrmsg.WlstTml.WlstSluD000
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		ff := &Fwd{
			DataCmd:  f.DataCmd,
			DataType: DataTypeBase64,
			DataDst:  "6",
			DstType:  SockUpgrade,
			Tra:      tra,
			Job:      JobSend,
			// Addr:     f.Addr,
			Src:     gopsu.Bytes2String(d, "-"),
			DataMsg: CodePb2(svrmsg),
		}
		lstf = append(lstf, ff)
	case 0x99: // 复位网络
		svrmsg.WlstTml.WlstSlu_9900 = &msgctl.WlstSlu_2400{}
		svrmsg.WlstTml.WlstSlu_9900.Status = int32(d[7])
		svrmsg.WlstTml.WlstSlu_9900.DoFlag = int32(d[8])
		zm := svrmsg.WlstTml.WlstSlu_9900
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xa4: // 启动/停止集中器
		svrmsg.WlstTml.WlstSluA400 = &msgctl.WlstSluF400{}
		svrmsg.WlstTml.WlstSluA400.Status = int32(d[7])
		zm := svrmsg.WlstTml.WlstSluA400
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xa8: // 设置集中器停运/投运，允许/禁止主动报警
		svrmsg.WlstTml.WlstSluA800 = &msgctl.WlstSluF400{}
		svrmsg.WlstTml.WlstSluA800.Status = int32(d[7])
		zm := svrmsg.WlstTml.WlstSluA800
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xb0: // 设置集中器参数
		svrmsg.WlstTml.WlstSluB000 = &msgctl.WlstSluF400{}
		svrmsg.WlstTml.WlstSluB000.Status = int32(d[7])
		zm := svrmsg.WlstTml.WlstSluB000
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xb2: // 招测集中器参数
		svrmsg.WlstTml.WlstSluB200 = &msgctl.WlstSlu_3000{}
		var a int64
		for i := 0; i < 8; i++ {
			a += int64(d[7+i]) * int64(math.Pow(256, float64(i)))
		}
		svrmsg.WlstTml.WlstSluB200.MacAddr = a
		svrmsg.WlstTml.WlstSluB200.Ctrls = int32(d[15]) + int32(d[16])*256
		svrmsg.WlstTml.WlstSluB200.DomainName = int32(d[17]) + int32(d[18])*256
		svrmsg.WlstTml.WlstSluB200.UpperVoltageLimit = int32(d[19]) + int32(d[20])*256
		svrmsg.WlstTml.WlstSluB200.LowerVoltageLimit = int32(d[21]) + int32(d[22])*256
		zm := svrmsg.WlstTml.WlstSluB200
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0x9a: // 招测控制器域名更改
		svrmsg.WlstTml.WlstSlu_9A00 = &msgctl.WlstSlu_9A00{}
		for i := 31; i > -1; i-- {
			svrmsg.WlstTml.WlstSlu_9A00.DomainNameStatus = append(svrmsg.WlstTml.WlstSlu_9A00.DomainNameStatus, gopsu.Byte2Int32s(d[7+i], true)...)
		}
		zm := svrmsg.WlstTml.WlstSlu_9A00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0x9d, 0xfa: // 选测（未知）控制器
		// svrmsg.WlstTml.WlstSlu_9D00 = &msgctl.WlstSlu_9D00{}
		// svrmsg.WlstTml.WlstSluFa00 = &msgctl.WlstSlu_9D00{}
		d9d := &msgctl.WlstSlu_9D00{}
		d9d.DataMark = &msgctl.WlstSlu_1D00_DataMark{}
		d9d.SluitemData = &msgctl.WlstSlu_9D00_SluitemData{}
		d9d.SluitemDataNew = &msgctl.WlstSlu_9D00_SluitemDataNew{}
		d9d.SluitemPara = &msgctl.WlstSlu_9D00_SluitemPara{}
		d9d.SluitemVer = &msgctl.WlstSlu_9D00_SluitemVer{}
		d9d.SluitemSunriseset = &msgctl.WlstSlu_9D00_SluitemSunriseset{}
		d9d.CmdIdx = int32(d[7])
		var j int
		if cmd == 0x9d {
			d9d.SluitemIdx = int64(d[8]) + int64(d[9])*256 + int64(d[10])*256*256 + int64(d[11])*256*256*256
			j = 12
		} else {
			d9d.SluitemIdx = int64(d[8]) + int64(d[9])*256
			j = 10
		}
		mark := fmt.Sprintf("%08b%08b", d[j+1], d[j])
		if gopsu.String2Int32(mark, 2) == 0 {
			d9d.Status = 0
			// mark = fmt.Sprintf("%08b%08b", d[j+2], d[j+1])
		} else {
			d9d.Status = 1
		}
		d9d.LoopCount = gopsu.String2Int32(mark[:3], 2) + 1
		j += 2
		if mark[15] == 49 { // 选测
			d9d.DataMark.ReadData = 1
			d9d.SluitemData.Voltage = (float64(d[j]) + float64(d[j+1])*256) / 100.0
			j += 2
			for i := int32(0); i < d9d.LoopCount; i++ {
				d9d.SluitemData.Current = append(d9d.SluitemData.Current, float64(int(d[j])+int(d[j+1])*256)/100.0)
				j += 2
			}
			for i := int32(0); i < d9d.LoopCount; i++ {
				d9d.SluitemData.ActivePower = append(d9d.SluitemData.ActivePower, float64(int(d[j])+int(d[j+1])*256)/10.0)
				j += 2
			}
			for i := int32(0); i < d9d.LoopCount; i++ {
				d9d.SluitemData.ReactivePower = append(d9d.SluitemData.ReactivePower, float64(int(d[j])+int(d[j+1])*256)/10.0)
				j += 2
			}
			d9d.SluitemData.MaxVoltage = float64(int(d[j])+int(d[j+1])*256) / 100.0
			j += 2
			for i := int32(0); i < d9d.LoopCount; i++ {
				d9d.SluitemData.MaxCurrent = append(d9d.SluitemData.MaxCurrent, float64(int(d[j])+int(d[j+1])*256)/100.0)
				j += 2
			}
			for i := int32(0); i < d9d.LoopCount; i++ {
				d9d.SluitemData.TotalElectricity = append(d9d.SluitemData.TotalElectricity, float64(d[j]))
				j++
			}
			for i := int32(0); i < d9d.LoopCount; i++ {
				ls := &msgctl.WlstSlu_7300_BaseSluitemData_LightStatus{}
				s := fmt.Sprintf("%08b", d[j])
				ls.WorkingOn = gopsu.String2Int32(s[6:8], 2)
				ls.Fault = gopsu.String2Int32(s[3:6], 2)
				ls.Leakage = gopsu.String2Int32(s[2:3], 2)
				ls.PowerStatus = gopsu.String2Int32(s[:2], 2)
				j++
				d9d.SluitemData.LightStatus = append(d9d.SluitemData.LightStatus, ls)
			}
			d9d.SluitemData.LeakageCurrent = float64(d[j]) / 100.0
			j++
			s := fmt.Sprintf("%08b", d[j])
			if s[0] == 49 {
				d9d.SluitemData.Temperature = 0 - gopsu.String2Int32(s[1:], 2)
			} else {
				d9d.SluitemData.Temperature = gopsu.String2Int32(s[1:], 2)
			}
			j++
			s = fmt.Sprintf("%08b", d[j])
			d9d.SluitemData.SluitemStatus = &msgctl.WlstSlu_7300_BaseSluitemData_SluitemStatus{}
			d9d.SluitemData.SluitemStatus.TemperatureSensor = gopsu.String2Int32(s[7:8], 2)
			d9d.SluitemData.SluitemStatus.EepromError = gopsu.String2Int32(s[6:7], 2)
			d9d.SluitemData.SluitemStatus.OffLine = gopsu.String2Int32(s[5:6], 2)
			d9d.SluitemData.SluitemStatus.NoAlarm = gopsu.String2Int32(s[4:5], 2)
			d9d.SluitemData.SluitemStatus.WorkingArgs = gopsu.String2Int32(s[3:4], 2)
			d9d.SluitemData.SluitemStatus.Adjust = gopsu.String2Int32(s[2:3], 2)
			j++
			d9d.SluitemData.TimerError = int32(d[j])
			j++
			d9d.SluitemData.ResetCount = int32(d[j])
			j += 6
		}
		if mark[14] == 49 { // 读取时钟
			d9d.DataMark.ReadTimer = 1
			d9d.SluitemTime = gopsu.Time2Stamp(fmt.Sprintf("20%02d-%02d-%02d %02d:%02d:%02d", d[j], d[j+1], d[j+2], d[j+3], d[j+4], d[j+5]))
			j += 6
		}
		if mark[13] == 49 { // 读取运行参数
			d9d.DataMark.ReadArgs = 1
			x, _ := strconv.ParseFloat(fmt.Sprintf("%d.%02d", d[j], int(d[j+1])), 10)
			d9d.SluitemPara.Longitude = x
			j += 2
			x, _ = strconv.ParseFloat(fmt.Sprintf("%d.%02d", d[j], int(d[j+1])), 10)
			d9d.SluitemPara.Latitude = x
			j += 2
			d9d.SluitemPara.DomainName = int32(d[j]) + int32(d[j+1])*256
			j += 2
			s := fmt.Sprintf("%08b", d[j])
			y, _ := strconv.ParseInt(s[:4], 2, 0)
			if y == 5 {
				d9d.SluitemPara.SluitemEnableAlarm = 1
			} else {
				d9d.SluitemPara.SluitemEnableAlarm = 0
			}
			y, _ = strconv.ParseInt(s[4:], 2, 0)
			if y == 5 {
				d9d.SluitemPara.SluitemStatus = 1
			} else {
				d9d.SluitemPara.SluitemStatus = 0
			}
			j++
			s = fmt.Sprintf("%08b", d[j])
			for i := int32(0); i < d9d.LoopCount; i++ {
				if s[8-(i+1):8-i] == "0" {
					d9d.SluitemPara.SluitemPowerTurnon = append(d9d.SluitemPara.SluitemPowerTurnon, 1)
				} else {
					d9d.SluitemPara.SluitemPowerTurnon = append(d9d.SluitemPara.SluitemPowerTurnon, 0)
				}
			}
			j++
			s = fmt.Sprintf("%08b", d[j])
			for i := int32(0); i < d9d.LoopCount; i++ {
				y, _ = strconv.ParseInt(s[8-(i*2+2):8-i*2], 2, 0)
				d9d.SluitemPara.SluitemVector = append(d9d.SluitemPara.SluitemVector, int32(y))
			}
			j++
			s = fmt.Sprintf("%08b%08b", d[j+1], d[j])
			for i := int32(0); i < d9d.LoopCount; i++ {
				y, _ = strconv.ParseInt(s[16-(i*4+4):16-i*4], 2, 0)
				d9d.SluitemPara.RatedPower = append(d9d.SluitemPara.RatedPower, int32(y))
			}
			j += 3
		}
		if mark[11] == 49 { // 读取组地址
			d9d.DataMark.ReadGroup = 1
			d9d.SluitemGroup = append(d9d.SluitemGroup, int32(d[j]), int32(d[j+1]), int32(d[j+2]), int32(d[j+3]), int32(d[j+4]))
			j += 5
		}
		if mark[10] == 49 { // 读取版本
			d9d.DataMark.ReadVer = 1
			s := fmt.Sprintf("%08b%08b", d[j+1], d[j])
			d9d.SluitemVer.SluitemLoop = gopsu.String2Int32(s[13:16], 2) + 1
			d9d.SluitemVer.EnergySaving = gopsu.String2Int32(s[10:13], 2)
			d9d.SluitemVer.ElectricLeakageModule = gopsu.String2Int32(s[9:10], 2)
			d9d.SluitemVer.TemperatureModule = gopsu.String2Int32(s[8:9], 2)
			d9d.SluitemVer.TimerModule = gopsu.String2Int32(s[7:8], 2)
			x, _ := strconv.ParseInt(s[:4], 2, 0)
			switch x {
			case 0:
				d9d.SluitemVer.SluitemType = "unknow"
			case 1:
				d9d.SluitemVer.SluitemType = "wj2190"
			case 2:
				d9d.SluitemVer.SluitemType = "wj2090j"
			case 3:
				d9d.SluitemVer.SluitemType = "wj5090"
			case 4:
				d9d.SluitemVer.SluitemType = "wj2090k"
			case 5:
				d9d.SluitemVer.SluitemType = "wj2290"
			case 6:
				d9d.SluitemVer.SluitemType = "wj2080c"
			case 8:
				d9d.SluitemVer.SluitemType = "wj2080d"
			case 9:
				d9d.SluitemVer.SluitemType = "wj4090b"
			case 10:
				d9d.SluitemVer.SluitemType = "wj2090l"
			case 12:
				d9d.SluitemVer.SluitemType = "wj2090m"
			case 14:
				d9d.SluitemVer.SluitemType = "wj4090a"
			default:
				d9d.SluitemVer.SluitemType = "unknow"
			}
			j += 2
			d9d.SluitemVer.Ver = string(d[j : j+20])
			j += 20
		}
		if mark[9] == 49 { // 读取当天日出日落
			d9d.DataMark.ReadSunriseset = 1
			d9d.SluitemSunriseset.Sunrise = int32(d[j])*60 + int32(d[j+1])
			j += 2
			d9d.SluitemSunriseset.Sunset = int32(d[j])*60 + int32(d[j+1])
			j += 2
		}
		if mark[6] == 49 { // 读取本地参数（新）
			d9d.DataMark.ReadTimetable = 1
			if d9d.Status == 1 {
				s := fmt.Sprintf("%08b", d[j])
				c := int(gopsu.String2Int32(s[2:], 2))
				j++
				// 加入是否有后续数据返回
				if s[0] == 49 {
					d9d.DataContinue = 1
				}
				mtype := fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
				j += 4
				for i := 0; i < c; i++ {
					cr := &msgctl.WlstSlu_9D00_SluitemRuntime{}
					cr.DataType = gopsu.String2Int32(mtype[32-i-1:32-1], 2)
					m := fmt.Sprintf("%08b", d[j])
					cr.OutputType = gopsu.String2Int32(m[4:], 2)
					cr.OperateType = gopsu.String2Int32(m[:4], 2)
					m = fmt.Sprintf("%08b", d[j+1])
					for k := 0; k < 7; k++ {
						cr.DateEnable = append(cr.DateEnable, gopsu.String2Int32(m[7-k:8-k], 2))
					}
					switch cr.OperateType {
					case 1:
						cr.OperateTime = int32(d[j+2])*60 + int32(d[j+3])
					case 2:
						m = fmt.Sprintf("%016b", int32(d[j+2])*60+int32(d[j+3]))
						y := gopsu.String2Int32(m[1:], 2)
						if m[0] == 49 {
							cr.OperateOffset = 0 - int32(y)
						} else {
							cr.OperateOffset = int32(y)
						}
					}
					m = fmt.Sprintf("%08b", d[j+4])
					n := fmt.Sprintf("%08b", d[j+5])
					switch cr.OutputType {
					case 1:
						y, _ := strconv.ParseInt(m[4:], 2, 0)
						x, _ := strconv.ParseInt(m[:4], 2, 0)
						cr.RelayOperate = append(cr.RelayOperate, int32(y), int32(x))
						y, _ = strconv.ParseInt(n[4:], 2, 0)
						x, _ = strconv.ParseInt(n[:4], 2, 0)
						cr.RelayOperate = append(cr.RelayOperate, int32(y), int32(x))
					case 2:
						cr.PwmLoop = append(cr.PwmLoop, int32(m[7]), int32(m[6]), int32(m[5]), int32(m[4]))
						x, _ := strconv.ParseInt(m[:4], 2, 0)
						y, _ := strconv.ParseInt(n[:4], 2, 0)
						cr.PwmPower = int32(x)*10 + int32(y)
						z, _ := strconv.ParseInt(n[4:], 2, 0)
						cr.PwmBaudrate = int32(z) * 100
					}
					j += 6
					d9d.SluitemRuntime = append(d9d.SluitemRuntime, cr)
				}
			}
		}
		if mark[5] == 49 { // 选测（新）
			d9d.DataMark.ReadCtrldata = 1
			for i := int32(0); i < d9d.LoopCount; i++ {
				d9d.SluitemDataNew.Voltage = append(d9d.SluitemDataNew.Voltage, float64(int(d[j])+int(d[j+1])*256)/100.0)
				j += 2
			}
			for i := int32(0); i < d9d.LoopCount; i++ {
				d9d.SluitemDataNew.Current = append(d9d.SluitemDataNew.Current, float64(int(d[j])+int(d[j+1])*256)/100.0)
				j += 2
			}
			for i := int32(0); i < d9d.LoopCount; i++ {
				d9d.SluitemDataNew.ActivePower = append(d9d.SluitemDataNew.ActivePower, float64(int(d[j])+int(d[j+1])*256)/10.0)
				j += 2
			}
			for i := int32(0); i < d9d.LoopCount; i++ {
				d9d.SluitemDataNew.TotalElectricity = append(d9d.SluitemDataNew.TotalElectricity, float64(int(d[j])+int(d[j+1])*256)/10.0)
				j += 2
			}
			for i := int32(0); i < d9d.LoopCount; i++ {
				d9d.SluitemDataNew.RunTime = append(d9d.SluitemDataNew.RunTime, int32(d[j])+int32(d[j+1])*256+int32(d[j+2])*256*256)
				j += 3
			}
			for i := int32(0); i < d9d.LoopCount; i++ {
				s := fmt.Sprintf("%08b", d[j])
				ls := &msgctl.WlstSlu_7300_BaseSluitemData_LightStatus{}
				ls.WorkingOn = gopsu.String2Int32(s[6:8], 2)
				ls.Fault = gopsu.String2Int32(s[3:6], 2)
				ls.Leakage = gopsu.String2Int32(s[2:3], 2)
				ls.PowerStatus = gopsu.String2Int32(s[:2], 2)
				j++
				d9d.SluitemDataNew.LightStatus = append(d9d.SluitemDataNew.LightStatus, ls)
			}
			d9d.SluitemDataNew.LeakageCurrent = float64(d[j]) / 100.0
			j++
			s := fmt.Sprintf("%08b", d[j])
			d9d.SluitemDataNew.SluitemStatus = &msgctl.WlstSlu_7300_BaseSluitemData_SluitemStatus{}
			d9d.SluitemDataNew.SluitemStatus.TemperatureSensor = gopsu.String2Int32(s[7:8], 2)
			d9d.SluitemDataNew.SluitemStatus.EepromError = gopsu.String2Int32(s[6:7], 2)
			d9d.SluitemDataNew.SluitemStatus.OffLine = gopsu.String2Int32(s[5:6], 2)
			d9d.SluitemDataNew.SluitemStatus.NoAlarm = gopsu.String2Int32(s[4:5], 2)
			d9d.SluitemDataNew.SluitemStatus.WorkingArgs = gopsu.String2Int32(s[3:4], 2)
			d9d.SluitemDataNew.SluitemStatus.Adjust = gopsu.String2Int32(s[2:3], 2)
			j++
			d9d.SluitemDataNew.TimerError = int32(d[j])
			j++
			d9d.SluitemDataNew.ResetCount = int32(d[j])
			j++
			s = fmt.Sprintf("%08b", d[j])
			d9d.SluitemDataNew.Phase = gopsu.String2Int32(s[4:], 2)
			j++
			x1 := fmt.Sprintf("%08b%08b", d[j+1], d[j])
			x2 := fmt.Sprintf("%08b%08b", d[j+3], d[j+2])
			d9d.SluitemDataNew.EnergySaving = append(d9d.SluitemDataNew.EnergySaving,
				gopsu.String2Int32(fmt.Sprintf("%d%d", gopsu.String2Int32(x1[12:], 2), gopsu.String2Int32(x2[12:], 2)), 10),
				gopsu.String2Int32(fmt.Sprintf("%d%d", gopsu.String2Int32(x1[8:12], 2), gopsu.String2Int32(x2[8:12], 2)), 10),
				gopsu.String2Int32(fmt.Sprintf("%d%d", gopsu.String2Int32(x1[4:8], 2), gopsu.String2Int32(x2[4:8], 2)), 10),
				gopsu.String2Int32(fmt.Sprintf("%d%d", gopsu.String2Int32(x1[:4], 2), gopsu.String2Int32(x2[:4], 2)), 10))
			j += 4
			j += 3
		}
		svrmsg.WlstTml.WlstSlu_9D00 = d9d
		svrmsg.WlstTml.WlstSluFa00 = d9d

		zm := svrmsg.WlstTml.WlstSluFa00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xcd: // 选测集中器报警参数
		svrmsg.WlstTml.WlstSluCd00 = &msgctl.WlstSluCd00{}
		svrmsg.WlstTml.WlstSluCd00.CommunicationFailures = int32(d[7])
		svrmsg.WlstTml.WlstSluCd00.PowerFactor = int32(d[8])
		svrmsg.WlstTml.WlstSluCd00.CommunicationChannel = gopsu.String2Int32(fmt.Sprintf("%08b%08b", d[10], d[9]), 2)
		svrmsg.WlstTml.WlstSluCd00.CurrentRange = float64(d[11]) / 10.0
		svrmsg.WlstTml.WlstSluCd00.PowerRange = int32(d[12]) * 10
		svrmsg.WlstTml.WlstSluCd00.AutoMode = int32(d[13])
		x, _ := strconv.ParseFloat(fmt.Sprintf("%d.%02d", d[14], d[15]), 10)
		svrmsg.WlstTml.WlstSluCd00.Longitude = x
		x, _ = strconv.ParseFloat(fmt.Sprintf("%d.%02d", d[16], d[17]), 10)
		svrmsg.WlstTml.WlstSluCd00.Latitude = x
		svrmsg.WlstTml.WlstSluCd00.CarrierRoutingMode = int32(d[18])
		svrmsg.WlstTml.WlstSluCd00.BluetoothPin = int32(d[19]) + int32(d[20])*256 + int32(d[21])*256*256 + int32(d[22])*256*256*256
		svrmsg.WlstTml.WlstSluCd00.BluetoothMode = int32(d[23])
		svrmsg.WlstTml.WlstSluCd00.Cct = int32(d[24])
		zm := svrmsg.WlstTml.WlstSluCd00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xee: // 招测/应答延迟巡测
		svrmsg.WlstTml.WlstSluEe00 = &msgctl.WlstSlu_6E00{}
		svrmsg.WlstTml.WlstSluEe00.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstSluEe00.DoFlag = int32(d[8])
		if d[8] == 2 {
			svrmsg.WlstTml.WlstSluEe00.PatrolStart = int32(d[9])*60 + int32(d[10])
			svrmsg.WlstTml.WlstSluEe00.PatrolInterval = int32(d[11])
			svrmsg.WlstTml.WlstSluEe00.PatrolOrder = int32(d[12]) - 1
			svrmsg.WlstTml.WlstSluEe00.PatrolCount = int32(d[13])
		}
		zm := svrmsg.WlstTml.WlstSluEe00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xf0: // 复位集中器
		svrmsg.WlstTml.WlstSluF000 = &msgctl.WlstSluF000{}
		svrmsg.WlstTml.WlstSluF000.ResetMark = &msgctl.WlstSluF000_ResetMark{}
		svrmsg.WlstTml.WlstSluF000.CmdIdx = int32(d[7])
		s := fmt.Sprintf("%08b", d[8])
		svrmsg.WlstTml.WlstSluF000.ResetMark.ResetConcentrator = gopsu.String2Int32(s[7:8], 2)
		svrmsg.WlstTml.WlstSluF000.ResetMark.HardResetZigbee = gopsu.String2Int32(s[6:7], 2)
		svrmsg.WlstTml.WlstSluF000.ResetMark.SoftResetZigbee = gopsu.String2Int32(s[5:6], 2)
		svrmsg.WlstTml.WlstSluF000.ResetMark.ResetCarrier = gopsu.String2Int32(s[4:5], 2)
		svrmsg.WlstTml.WlstSluF000.ResetMark.InitAll = gopsu.String2Int32(s[3:4], 2)
		svrmsg.WlstTml.WlstSluF000.ResetMark.ClearData = gopsu.String2Int32(s[2:3], 2)
		svrmsg.WlstTml.WlstSluF000.ResetMark.ClearArgs = gopsu.String2Int32(s[1:2], 2)
		svrmsg.WlstTml.WlstSluF000.ResetMark.ClearTask = gopsu.String2Int32(s[0:1], 2)
		zm := svrmsg.WlstTml.WlstSluF000
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xf1: // 时钟设置
		svrmsg.WlstTml.WlstSluF100 = &msgctl.WlstSluF100{}
		svrmsg.WlstTml.WlstSluF100.TimerStatus = &msgctl.WlstSluF100_TimerStatus{}
		svrmsg.WlstTml.WlstSluF100.CmdIdx = int32(d[7])
		s := fmt.Sprintf("%08b", d[8])
		svrmsg.WlstTml.WlstSluF100.TimerStatus.DtformatError = gopsu.String2Int32(s[7:8], 2)
		svrmsg.WlstTml.WlstSluF100.TimerStatus.TimerError = gopsu.String2Int32(s[6:7], 2)
		svrmsg.WlstTml.WlstSluF100.TimerStatus.TimeFault = gopsu.String2Int32(s[5:6], 2)
		s = fmt.Sprintf("%08b", d[9])
		svrmsg.WlstTml.WlstSluF100.ForceTimer = gopsu.String2Int32(s[7:8], 2)
		svrmsg.WlstTml.WlstSluF100.OptMark = gopsu.String2Int32(s[:1], 2)
		svrmsg.WlstTml.WlstSluF100.DateTime = gopsu.Time2Stamp(fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", int32(d[10])+2000, d[11], d[12], d[13], d[14], d[15]))
		// if math.Abs(float64(int64(time.Now().Unix())-svrmsg.WlstTml.WlstSluF100.DateTime)) > 60 { // 强制对时
		// 	ff := &Fwd{
		// 		Addr:     f.Addr,
		// 		DataType: DataTypeBytes,
		// 		DataPT:   1000,
		// 		DataDst:  fmt.Sprintf("wlst-slu-%d", f.Addr),
		// 		DstType:  1,
		// 		Tra:      tra,
		// 		Job:      JobSend,
		// 		Src:      gopsu.Bytes2String(d, "-"),
		// 		DataMsg:  gopsu.Bytes2String(GetServerTimeMsg(f.Addr, 2, false, false), "-"),
		// 	}
		// 	lstf = append(lstf, ff)
		// }
		zm := svrmsg.WlstTml.WlstSluF100
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xf2: // 读控制器参数
		svrmsg.WlstTml.WlstSluF200 = &msgctl.WlstSluF200{}
		svrmsg.WlstTml.WlstSluF200.DataMark = &msgctl.WlstSluF200_DataMark{}
		svrmsg.WlstTml.WlstSluF200.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstSluF200.SluitemIdx = int32(d[8]) + int32(d[9])*256
		svrmsg.WlstTml.WlstSluF200.SluitemCount = int32(d[10])
		m := fmt.Sprintf("%08b%08b", d[12], d[11])
		svrmsg.WlstTml.WlstSluF200.DataMark.SetData = gopsu.String2Int32(m[:1], 2)
		svrmsg.WlstTml.WlstSluF200.DataMark.Group = gopsu.String2Int32(m[15:16], 2)
		svrmsg.WlstTml.WlstSluF200.DataMark.Barcode = gopsu.String2Int32(m[14:15], 2)
		svrmsg.WlstTml.WlstSluF200.DataMark.Route = gopsu.String2Int32(m[13:14], 2)
		svrmsg.WlstTml.WlstSluF200.DataMark.Order = gopsu.String2Int32(m[12:13], 2)
		svrmsg.WlstTml.WlstSluF200.DataMark.Limit = gopsu.String2Int32(m[11:12], 2)
		svrmsg.WlstTml.WlstSluF200.DataMark.PowerOnStatus = gopsu.String2Int32(m[10:11], 2)
		svrmsg.WlstTml.WlstSluF200.DataMark.RunStatus = gopsu.String2Int32(m[9:10], 2)
		svrmsg.WlstTml.WlstSluF200.DataMark.Vector = gopsu.String2Int32(m[8:9], 2)
		svrmsg.WlstTml.WlstSluF200.DataMark.RatedPower = gopsu.String2Int32(m[7:8], 2)
		if m[0] == 49 {
			svrmsg.WlstTml.WlstSluF200.Status = int32(d[13])
		} else {
			if m[1] == 48 {
				svrmsg.WlstTml.WlstSluF200.Status = 1
			} else {
				svrmsg.WlstTml.WlstSluF200.Status = 0
			}
			j := 13
			for i := byte(0); i < d[10]; i++ {
				cr := &msgctl.WlstSluF200_ControllerData{}
				if svrmsg.WlstTml.WlstSluF200.DataMark.Group == 1 && svrmsg.WlstTml.WlstSluF200.Status == 1 {
					cr.SluitemGroup = append(cr.SluitemGroup, int32(d[j]), int32(d[j+1]), int32(d[j+2]), int32(d[j+3]), int32(d[j+4]))
					j += 5
				}
				if svrmsg.WlstTml.WlstSluF200.DataMark.Barcode == 1 && svrmsg.WlstTml.WlstSluF200.Status == 1 {
					cr.SluitemIdx = int64(d[j]) + int64(d[j+1])*256 + int64(d[j+2])*256*256 + int64(d[j+3])*256*256*256
					j += 4
				}
				if svrmsg.WlstTml.WlstSluF200.DataMark.Route == 1 && svrmsg.WlstTml.WlstSluF200.Status == 1 {
					cr.SluitemRoute = append(cr.SluitemRoute, int32(d[j]), int32(d[j+1]), int32(d[j+2]), int32(d[j+3]))
					j += 4
				}
				if svrmsg.WlstTml.WlstSluF200.DataMark.Order == 1 && svrmsg.WlstTml.WlstSluF200.Status == 1 {
					cr.SluitemOrder = int32(d[j])
					j++
				}
				if svrmsg.WlstTml.WlstSluF200.DataMark.Limit == 1 && svrmsg.WlstTml.WlstSluF200.Status == 1 {
					cr.UpperPowerLimit = int32(d[j])
					cr.LowerPowerLimit = int32(d[j+1])
					j += 2
				}
				if svrmsg.WlstTml.WlstSluF200.DataMark.PowerOnStatus == 1 && svrmsg.WlstTml.WlstSluF200.Status == 1 {
					m := fmt.Sprintf("%08b", d[j])
					if m[7] == 48 {
						cr.SluitemPowerTurnon = append(cr.SluitemPowerTurnon, 1)
					} else {
						cr.SluitemPowerTurnon = append(cr.SluitemPowerTurnon, 0)
					}
					if m[6] == 48 {
						cr.SluitemPowerTurnon = append(cr.SluitemPowerTurnon, 1)
					} else {
						cr.SluitemPowerTurnon = append(cr.SluitemPowerTurnon, 0)
					}
					if m[5] == 48 {
						cr.SluitemPowerTurnon = append(cr.SluitemPowerTurnon, 1)
					} else {
						cr.SluitemPowerTurnon = append(cr.SluitemPowerTurnon, 0)
					}
					if m[4] == 48 {
						cr.SluitemPowerTurnon = append(cr.SluitemPowerTurnon, 1)
					} else {
						cr.SluitemPowerTurnon = append(cr.SluitemPowerTurnon, 0)
					}
					j++
				}
				if svrmsg.WlstTml.WlstSluF200.DataMark.RunStatus == 1 && svrmsg.WlstTml.WlstSluF200.Status == 1 {
					m := fmt.Sprintf("%08b", d[j])
					if gopsu.String2Int32(m[4:], 2) == 5 {
						cr.SluitemStatus = 1
					} else {
						cr.SluitemStatus = 0
					}
					if gopsu.String2Int32(m[:4], 2) == 5 {
						cr.SluitemEnableAlarm = 1
					} else {
						cr.SluitemEnableAlarm = 0
					}
					j++
				}
				if svrmsg.WlstTml.WlstSluF200.DataMark.Vector == 1 && svrmsg.WlstTml.WlstSluF200.Status == 1 {
					m := fmt.Sprintf("%08b", d[j])
					cr.SluitemVector = append(cr.SluitemVector, gopsu.String2Int32(m[6:8], 2)+1,
						gopsu.String2Int32(m[4:6], 2)+1,
						gopsu.String2Int32(m[2:4], 2)+1,
						gopsu.String2Int32(m[:2], 2)+1)
					j++
				}
				if svrmsg.WlstTml.WlstSluF200.DataMark.RatedPower == 1 && svrmsg.WlstTml.WlstSluF200.Status == 1 {
					m := fmt.Sprintf("%08b%08b", d[j+1], d[j])
					cr.RatedPower = append(cr.RatedPower, gopsu.String2Int32(m[12:16], 2),
						gopsu.String2Int32(m[8:12], 2),
						gopsu.String2Int32(m[4:8], 2),
						gopsu.String2Int32(m[:4], 2))
					j += 2
				}
				svrmsg.WlstTml.WlstSluF200.SluitemData = append(svrmsg.WlstTml.WlstSluF200.SluitemData, cr)
			}
		}
		zm := svrmsg.WlstTml.WlstSluF200
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xf3: // 选测
		svrmsg.WlstTml.WlstSluF300 = &msgctl.WlstSlu_7300{}
		svrmsg.WlstTml.WlstSluF300.CmdIdx = int32(d[7])
		m := fmt.Sprintf("%08b%08b", d[9], d[8])
		svrmsg.WlstTml.WlstSluF300.SluitemStart = gopsu.String2Int32(m[4:], 2)
		svrmsg.WlstTml.WlstSluF300.DataMark = gopsu.String2Int32(m[:4], 2)
		switch svrmsg.WlstTml.WlstSluF300.DataMark {
		case 0: // 选测集中器
			svrmsg.WlstTml.WlstSluF300.ConcentratorData = &msgctl.WlstSlu_7300_ConcentratorData{}
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.RunStatus = &msgctl.WlstSlu_7300_ConcentratorData_RunStatus{}
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.ArgsStatus = &msgctl.WlstSlu_7300_ConcentratorData_ArgsStatus{}
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.HardwareStatus = &msgctl.WlstSlu_7300_ConcentratorData_HardwareStatus{}
			for i := 0; i < 4; i++ {
				svrmsg.WlstTml.WlstSluF300.ConcentratorData.ResetCount = append(svrmsg.WlstTml.WlstSluF300.ConcentratorData.ResetCount, int32(d[10+i]))
			}
			m := fmt.Sprintf("%08b", d[14])
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.RunStatus.Offline = gopsu.String2Int32(m[7:8], 2)
			if gopsu.String2Int32(m[6:7], 2) == 1 {
				svrmsg.WlstTml.WlstSluF300.ConcentratorData.RunStatus.EnableAlarm = 0
			} else {
				svrmsg.WlstTml.WlstSluF300.ConcentratorData.RunStatus.EnableAlarm = 1
			}
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.RunStatus.PoweronMark = gopsu.String2Int32(m[5:6], 2)
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.RunStatus.EnableGprs = gopsu.String2Int32(m[4:5], 2)
			if gopsu.String2Int32(m[3:4], 2) == 1 {
				svrmsg.WlstTml.WlstSluF300.ConcentratorData.RunStatus.EnableAutochk = 0
			} else {
				svrmsg.WlstTml.WlstSluF300.ConcentratorData.RunStatus.EnableAutochk = 1
			}
			m = fmt.Sprintf("%08b", d[15])
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.ArgsStatus.ConcentratorArgsError = gopsu.String2Int32(m[7:8], 2)
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.ArgsStatus.SluitemArgsError = gopsu.String2Int32(m[6:7], 2)
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.ArgsStatus.TurnOnoffError = gopsu.String2Int32(m[5:6], 2)
			m = fmt.Sprintf("%08b", d[16])
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.HardwareStatus.ZigbeeError = gopsu.String2Int32(m[7:8], 2)
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.HardwareStatus.CarrierError = gopsu.String2Int32(m[6:7], 2)
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.HardwareStatus.FramError = gopsu.String2Int32(m[5:6], 2)
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.HardwareStatus.BluetoothError = gopsu.String2Int32(m[4:5], 2)
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.HardwareStatus.TimerError = gopsu.String2Int32(m[3:4], 2)
			svrmsg.WlstTml.WlstSluF300.ConcentratorData.UnknowSluitemCount = int32(d[17])
			if d[18] > 10 {
				svrmsg.WlstTml.WlstSluF300.ConcentratorData.CommunicationChannel = int32(d[18]) - 10
			} else {
				svrmsg.WlstTml.WlstSluF300.ConcentratorData.CommunicationChannel = 0
			}
		case 1, 5: // 选测控制器基本数据
			svrmsg.WlstTml.WlstSluF300.SluitemCount = int32(d[10])
			n := int(d[10]) / 4
			if d[10]%4 > 0 {
				n++
			}
			var s string
			for i := 0; i < n; i++ {
				s = fmt.Sprintf("%08b", d[11+i]) + s
			}
			var ctrlloop = make([]int32, 0)
			for i := len(s); i > 0; i -= 2 {
				ctrlloop = append(ctrlloop, gopsu.String2Int32(s[i-1:i], 2)+1)
			}
			j := 0
			for i := byte(0); i < d[10]; i++ {
				cbd := &msgctl.WlstSlu_7300_BaseSluitemData{}
				cbd.SluitemLoop = ctrlloop[i]
				if svrmsg.WlstTml.WlstSluF300.DataMark == 5 {
					s := fmt.Sprintf("%08b%08b", d[11+n+j+1], d[11+n+j])
					j += 2
					t := time.Now()
					dd := gopsu.String2Int32(s[:5], 2)
					h := gopsu.String2Int32(s[5:10], 2)
					mm := gopsu.String2Int32(s[10:16], 2)
					y := t.Year()
					m := t.Month()
					if dd > 0 && h >= 0 && h < 24 && mm < 61 && mm >= 0 {
						t1 := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:00", y, m, dd, h, mm)
						t2 := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:00", y, m, dd, t.Hour(), t.Minute())
						d1 := time.Unix(gopsu.Time2Stamp(t1), 0)
						if gopsu.Time2Stamp(t1)-gopsu.Time2Stamp(t2) < -1*60*20 {
							d1 = d1.AddDate(0, -1, 0)
						}
						cbd.DateTime = d1.Unix()
					} else {
						cbd.DateTime = 0
					}
				}
				m := fmt.Sprintf("%08b", d[11+n+j])
				j++
				cbd.SluitemStatus = &msgctl.WlstSlu_7300_BaseSluitemData_SluitemStatus{}
				cbd.SluitemStatus.Status = gopsu.String2Int32(m[:2], 2)
				cbd.SluitemStatus.Adjust = gopsu.String2Int32(m[2:3], 2)
				cbd.SluitemStatus.WorkingArgs = gopsu.String2Int32(m[3:4], 2)
				cbd.SluitemStatus.NoAlarm = gopsu.String2Int32(m[4:5], 2)
				cbd.SluitemStatus.OffLine = gopsu.String2Int32(m[5:6], 2)
				cbd.SluitemStatus.EepromError = gopsu.String2Int32(m[6:7], 2)
				cbd.SluitemStatus.TemperatureSensor = gopsu.String2Int32(m[7:8], 2)
				cbd.Temperature = int32(d[11+n+j])
				j++
				for k := int32(0); k < ctrlloop[i]; k++ {
					m = fmt.Sprintf("%08b", d[11+n+j])
					j++
					ls := &msgctl.WlstSlu_7300_BaseSluitemData_LightStatus{}
					ld := &msgctl.WlstSlu_7300_BaseSluitemData_LightData{}
					ls.PowerStatus = gopsu.String2Int32(m[:2], 2)
					ls.Leakage = gopsu.String2Int32(m[2:3], 2)
					ls.Fault = gopsu.String2Int32(m[3:6], 2)
					ls.WorkingOn = gopsu.String2Int32(m[6:8], 2)
					ld.Voltage = float64(d[11+n+j]) / 255.0 * 300.0
					j++
					ld.Current = float64(d[11+n+j]) / 255.0 * 300.0
					j++
					ld.ActivePower = float64(d[11+n+j]) / 255.0 * 300.0
					j++
					cbd.LightStatus = append(cbd.LightStatus, ls)
					cbd.LightData = append(cbd.LightData, ld)
				}
				svrmsg.WlstTml.WlstSluF300.BaseSluitemData = append(svrmsg.WlstTml.WlstSluF300.BaseSluitemData, cbd)
			}
		case 2: // 选测未知控制器
			svrmsg.WlstTml.WlstSluF300.SluitemCount = int32(d[10])
			j := 0
			for i := 0; i < int(d[10]); i++ {
				uc := &msgctl.WlstSlu_7300_UnknowSluitem{}
				uc.ModelInfo = &msgctl.WlstSlu_7300_ModelInfo{}
				uc.SluitemIdx = int64(d[11+j]) + int64(d[11+j+1])*256 + int64(d[11+j+2])*256*256 + int64(d[11+j+3])*256*256*256
				j += 4
				m := fmt.Sprintf("%08b%08b", d[11+j+1], d[11+j])
				j += 2
				uc.ModelInfo.Model = gopsu.String2Int32(m[:4], 2)
				switch uc.ModelInfo.Model {
				case 0:
					uc.ModelInfo.SluitemType = "unknow"
				case 1:
					uc.ModelInfo.SluitemType = "wj2190"
				case 2:
					uc.ModelInfo.SluitemType = "wj2090j"
				case 3:
					uc.ModelInfo.SluitemType = "wj5090"
				case 4:
					uc.ModelInfo.SluitemType = "wj2090k"
				case 5:
					uc.ModelInfo.SluitemType = "wj2290"
				case 6:
					uc.ModelInfo.SluitemType = "wj2080c"
				case 8:
					uc.ModelInfo.SluitemType = "wj2080d"
				case 9:
					uc.ModelInfo.SluitemType = "wj4090b"
				case 10:
					uc.ModelInfo.SluitemType = "wj2090l"
				case 12:
					uc.ModelInfo.SluitemType = "wj2090m"
				case 14:
					uc.ModelInfo.SluitemType = "wj4090a"
				default:
					uc.ModelInfo.SluitemType = "unknow"
				}
				uc.ModelInfo.HasTimer = gopsu.String2Int32(m[7:8], 2)
				uc.ModelInfo.HasTemperature = gopsu.String2Int32(m[8:9], 2)
				uc.ModelInfo.HasLeakage = gopsu.String2Int32(m[9:10], 2)
				uc.ModelInfo.PowerSaving = gopsu.String2Int32(m[10:13], 2)
				uc.ModelInfo.SluitemLoop = gopsu.String2Int32(m[13:16], 2) + 1
				svrmsg.WlstTml.WlstSlu_7300.UnknowSluitem = append(svrmsg.WlstTml.WlstSlu_7300.UnknowSluitem, uc)
			}
		case 3, 6: // 控制器辅助数据
			svrmsg.WlstTml.WlstSluF300.SluitemCount = int32(d[10])
			n := int(d[10]) / 4
			if d[10]%4 > 0 {
				n++
			}
			var s string
			for i := 0; i < n; i++ {
				s = fmt.Sprintf("%08b", d[11+i]) + s
			}
			var ctrlloop = make([]int32, 0)
			for i := len(s); i > 0; i -= 2 {
				ctrlloop = append(ctrlloop, gopsu.String2Int32(s[i-1:i], 2)+1)
			}
			j := 0
			for i := 0; i < int(d[10]); i++ {
				cd := &msgctl.WlstSlu_7300_AssistSluitemData{}
				cd.SluitemLoop = ctrlloop[i]
				if svrmsg.WlstTml.WlstSluF300.DataMark == 6 {
					s := fmt.Sprintf("%08b%08b", d[11+n+j+1], d[11+n+j])
					j += 2
					t := time.Now()
					dd := gopsu.String2Int32(s[:5], 2)
					h := gopsu.String2Int32(s[5:10], 2)
					mm := gopsu.String2Int32(s[10:16], 2)
					y := t.Year()
					m := t.Month()
					if dd > 0 && h >= 0 && h < 24 && mm < 61 && mm >= 0 {
						t1 := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:00", y, m, dd, h, mm)
						t2 := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:00", y, m, dd, t.Hour(), t.Minute())
						d1 := time.Unix(gopsu.Time2Stamp(t1), 0)
						if gopsu.Time2Stamp(t1)-gopsu.Time2Stamp(t2) < -1*60*20 {
							d1 = d1.AddDate(0, -1, 0)
						}
						cd.DateTime = d1.Unix()
					} else {
						cd.DateTime = 0
					}
				}
				cd.LeakageCurrent = float64(d[11+n+j])
				j++
				for k := int32(0); k < ctrlloop[i]; k++ {
					ld := &msgctl.WlstSlu_7300_AssistSluitemData_LightData{}
					ld.MaxVoltage = float64(d[11+n+j]) / 255.0 * 300
					j++
					ld.MaxCurrent = float64(d[11+n+j]) / 255.0 * 300
					j++
					ld.Electricity = float64(d[11+n+j]) / 255.0 * 300
					j++
					cd.LightData = append(cd.LightData, ld)
				}
				svrmsg.WlstTml.WlstSluF300.AssistSluitemData = append(svrmsg.WlstTml.WlstSluF300.AssistSluitemData, cd)
			}
		case 4: // 选测物理信息
			svrmsg.WlstTml.WlstSluF300.SluitemCount = int32(d[10])
			for i := 0; i < int(d[10])*4; i += 4 {
				m := fmt.Sprintf("%08b%08b%08b%08b", d[11+i+3], d[11+i+2], d[11+i+1], d[11+i])
				pi := &msgctl.WlstSlu_7300_SluitemPhyinfo{}
				pi.ModelInfo = &msgctl.WlstSlu_7300_ModelInfo{}
				pi.AllCommunicate = gopsu.String2Int32(m[:4], 2)
				pi.UsefulCommunicate = gopsu.String2Int32(m[4:8], 2)
				mi := m[8:22]
				pi.ModelInfo.Model = gopsu.String2Int32(mi[:4], 2)
				switch pi.ModelInfo.Model {
				case 0:
					pi.ModelInfo.SluitemType = "unknow"
				case 1:
					pi.ModelInfo.SluitemType = "wj2190"
				case 2:
					pi.ModelInfo.SluitemType = "wj2090j"
				case 3:
					pi.ModelInfo.SluitemType = "wj5090"
				case 4:
					pi.ModelInfo.SluitemType = "wj2090k"
				case 5:
					pi.ModelInfo.SluitemType = "wj2290"
				case 6:
					pi.ModelInfo.SluitemType = "wj2080c"
				case 8:
					pi.ModelInfo.SluitemType = "wj2080d"
				case 9:
					pi.ModelInfo.SluitemType = "wj4090b"
				case 10:
					pi.ModelInfo.SluitemType = "wj2090l"
				case 12:
					pi.ModelInfo.SluitemType = "wj2090m"
				case 14:
					pi.ModelInfo.SluitemType = "wj4090a"
				default:
					pi.ModelInfo.SluitemType = "unknow"
				}
				pi.ModelInfo.HasTimer = gopsu.String2Int32(mi[5:6], 2)
				pi.ModelInfo.HasTemperature = gopsu.String2Int32(mi[6:7], 2)
				pi.ModelInfo.HasLeakage = gopsu.String2Int32(mi[7:8], 2)
				pi.ModelInfo.PowerSaving = gopsu.String2Int32(mi[8:11], 2)
				pi.ModelInfo.SluitemLoop = gopsu.String2Int32(mi[11:14], 2) + 1
				pi.Phase = gopsu.String2Int32(m[22:24], 2)
				pi.Routing = gopsu.String2Int32(m[24:28], 2)
				pi.SignalStrength = gopsu.String2Int32(m[28:32], 2)
				svrmsg.WlstTml.WlstSluF300.SluitemPhyinfo = append(svrmsg.WlstTml.WlstSluF300.SluitemPhyinfo, pi)
			}
		case 7: // 选测，含电量，双字节数据
			svrmsg.WlstTml.WlstSluF300.SluitemCount = int32(d[10])
			for i := int32(0); i < int32(d[10]); i++ {
				svrmsg.WlstTml.WlstSluF300.SluitemAddrs = append(svrmsg.WlstTml.WlstSluF300.SluitemAddrs, svrmsg.WlstTml.WlstSluF300.SluitemStart+i)
			}
			n := int32(d[10]) / 4
			if d[10]%4 > 0 {
				n++
			}
			var s string
			for i := int32(0); i < n; i++ {
				s = fmt.Sprintf("%08b", d[11+i]) + s
			}
			var ctrlloop = make([]int32, 0)
			for i := len(s); i > 0; i -= 2 {
				ctrlloop = append(ctrlloop, gopsu.String2Int32(s[i-1:i], 2)+1)
			}
			j := int32(0)
			x := ll - 7 - n
			haspower := true
			z := int32(0)
			for i := byte(0); i < d[10]; i++ {
				switch ctrlloop[i] {
				case 1:
					z += 16
				case 2:
					z += 29
				case 3:
					z += 42
				case 4:
					z += 55
				}
			}
			if z != x {
				haspower = false
			}
			for i := byte(0); i < d[10]; i++ {
				cd := &msgctl.WlstSlu_7300_BaseSluitemData{}
				cd.SluitemStatus = &msgctl.WlstSlu_7300_BaseSluitemData_SluitemStatus{}
				cd.SluitemLoop = ctrlloop[i]
				s := fmt.Sprintf("%08b%08b", d[11+n+j+1], d[11+n+j])
				j += 2
				t := time.Now()
				dd := gopsu.String2Int32(s[:5], 2)
				h := gopsu.String2Int32(s[5:10], 2)
				mm := gopsu.String2Int32(s[10:16], 2)
				y := t.Year()
				m := t.Month()
				if dd > 0 && h >= 0 && h < 24 && mm < 61 && mm >= 0 {
					t1 := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:00", y, m, dd, h, mm)
					t2 := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:00", y, m, dd, t.Hour(), t.Minute())
					d1 := time.Unix(gopsu.Time2Stamp(t1), 0)
					if gopsu.Time2Stamp(t1)-gopsu.Time2Stamp(t2) < -1*60*20 {
						d1 = d1.AddDate(0, -1, 0)
					}
					cd.DateTime = d1.Unix()
				} else {
					cd.DateTime = 0
				}
				mark := fmt.Sprintf("%08b", d[11+n+j])
				j++
				cd.SluitemStatus.Status = gopsu.String2Int32(mark[:2], 2)
				cd.SluitemStatus.Adjust = gopsu.String2Int32(mark[2:3], 2)
				cd.SluitemStatus.WorkingArgs = gopsu.String2Int32(mark[3:4], 2)
				cd.SluitemStatus.NoAlarm = gopsu.String2Int32(mark[4:5], 2)
				cd.SluitemStatus.OffLine = gopsu.String2Int32(mark[5:6], 2)
				cd.SluitemStatus.EepromError = gopsu.String2Int32(mark[6:7], 2)
				cd.SluitemStatus.TemperatureSensor = gopsu.String2Int32(mark[7:8], 2)
				for k := int32(0); k < ctrlloop[i]; k++ {
					ls := &msgctl.WlstSlu_7300_BaseSluitemData_LightStatus{}
					ld := &msgctl.WlstSlu_7300_BaseSluitemData_LightData{}
					m := fmt.Sprintf("%08b", d[11+n+j])
					j++
					ls.PowerStatus = gopsu.String2Int32(m[:2], 2)
					ls.Leakage = gopsu.String2Int32(m[2:3], 2)
					ls.Fault = gopsu.String2Int32(m[3:6], 2)
					ls.WorkingOn = gopsu.String2Int32(m[6:8], 2)
					cd.LightStatus = append(cd.LightStatus, ls)
					ld.Voltage = (float64(d[11+n+j]) + float64(d[11+n+j+1])*256) / 100.0
					j += 2
					ld.Current = (float64(d[11+n+j]) + float64(d[11+n+j+1])*256) / 100.0
					j += 2
					ld.ActivePower = (float64(d[11+n+j]) + float64(d[11+n+j+1])*256) / 10.0
					j += 2
					ld.Electricity = (float64(d[11+n+j]) + float64(d[11+n+j+1])*256) / 10.0
					j += 2
					ld.ActiveTime = float64(d[11+n+j]) + float64(d[11+n+j+1])*256 + float64(d[11+n+j+2])*256*256
					j += 3
					if haspower {
						ld.PowerLevel = int32(d[11+n+j])
						j++
					}
					cd.LightData = append(cd.LightData, ld)
				}
				svrmsg.WlstTml.WlstSluF300.BaseSluitemData = append(svrmsg.WlstTml.WlstSluF300.BaseSluitemData, cd)
			}
		}
		zm := svrmsg.WlstTml.WlstSluF300
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xf8: // 招测事件
		svrmsg.WlstTml.WlstSluF800 = &msgctl.WlstSluF800{}
		svrmsg.WlstTml.WlstSluF800.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstSluF800.EventType = int32(d[8])
		svrmsg.WlstTml.WlstSluF800.ClassType = int32(d[9])
		svrmsg.WlstTml.WlstSluF800.DataTotal = int32(d[10])
		svrmsg.WlstTml.WlstSluF800.DataIdx = int32(d[11])
		svrmsg.WlstTml.WlstSluF800.RecordCount = int32(d[12])
		j := 13
		switch d[8] {
		case 0x20, 0x22, 0x24, 0x25:
			for i := 0; i < int(d[12]); i++ {
				dv := &msgctl.WlstSluF800_View0X20{}
				dv.DtHappen = gopsu.Time2Stamp(fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", int32(d[j])+2000, d[j+1], d[j+2], d[j+3], d[j+4], d[j+5]))
				j += 6
				if d[8] == 0x24 {
					dv.Status = append(dv.Status, gopsu.Byte2Int32s(d[j], true)...)
					dv.Status = append(dv.Status, gopsu.Byte2Int32s(d[j+1], true)...)
					j += 2
				} else {
					dv.Status = append(dv.Status, int32(d[j]))
					j++
				}
				switch d[8] {
				case 0x20:
					svrmsg.WlstTml.WlstSluF800.View_0X20 = append(svrmsg.WlstTml.WlstSluF800.View_0X20, dv)
				case 0x22:
					svrmsg.WlstTml.WlstSluF800.View_0X22 = append(svrmsg.WlstTml.WlstSluF800.View_0X22, dv)
				case 0x24:
					svrmsg.WlstTml.WlstSluF800.View_0X24 = append(svrmsg.WlstTml.WlstSluF800.View_0X24, dv)
				case 0x25:
					svrmsg.WlstTml.WlstSluF800.View_0X25 = append(svrmsg.WlstTml.WlstSluF800.View_0X25, dv)
				}
			}
		case 0x21:
			dv := &msgctl.WlstSluF800_View0X21{}
			dv.DtHappen = gopsu.Time2Stamp(fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", int32(d[j])+2000, d[j+1], d[j+2], d[j+3], d[j+4], d[j+5]))
			j += 6
			if (d[j] == 0 && d[j+1] == 0) || (d[j] == 0xff && d[j+1] == 0xff) {
				dv.AddrType = 0
			} else {
				if d[j] != 0xff && d[j+1] == 0xff {
					dv.AddrType = 1
				} else {
					if d[j] == 0xff && d[j+1] != 0xff {
						dv.AddrType = 2
					} else {
						dv.AddrType = 3
					}
				}
			}
			j += 2
			s := fmt.Sprintf("%08b", d[j])
			dv.OperationOrder = gopsu.String2Int32(s[:4], 2)
			dv.OperationType = gopsu.String2Int32(s[4:], 2)
			j++
			dv.OperationSource = int32(d[j])
			j++
			svrmsg.WlstTml.WlstSluF800.View_0X21 = append(svrmsg.WlstTml.WlstSluF800.View_0X21, dv)
		case 0x23:
			dv := &msgctl.WlstSluF800_View0X23{}
			dv.DtHappen = gopsu.Time2Stamp(fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", int32(d[j])+2000, d[j+1], d[j+2], d[j+3], d[j+4], d[j+5]))
			j += 6
			dv.Addr = int32(d[j]) + int32(d[j+1])*256
			j += 2
			dv.AlarmType = append(dv.AlarmType, gopsu.Byte2Int32s(d[j], true)...)
			dv.AlarmType = append(dv.AlarmType, gopsu.Byte2Int32s(d[j+1], true)...)
			j += 2
			s := fmt.Sprintf("%08b", d[j])
			dv.SluitemStatus = append(dv.SluitemStatus, gopsu.Byte2Int32s(gopsu.String2Int8(s[2:], 2), false)...)
			switch gopsu.String2Int32(s[:2], 2) {
			case 1:
				dv.SluitemStatus = append(dv.SluitemStatus, 1, 0, 0)
			case 2:
				dv.SluitemStatus = append(dv.SluitemStatus, 0, 1, 0)
			case 3:
				dv.SluitemStatus = append(dv.SluitemStatus, 0, 0, 1)
			}
			j++
			dv.SluitemVoltage = (float64(d[j+1])*256.0 + float64(d[j])) / 100.0
			j += 2
			dv.SluitemCurrent = append(dv.SluitemCurrent,
				(float64(d[j+1])*256.0+float64(d[j]))/100.0,
				(float64(d[j+3])*256.0+float64(d[j+2]))/100.0,
				(float64(d[j+5])*256.0+float64(d[j+4]))/100.0,
				(float64(d[j+7])*256.0+float64(d[j+6]))/100.0)
			j += 8
			dv.SluitemActivePower = append(dv.SluitemActivePower,
				(float64(d[j+1])*256.0+float64(d[j]))/100.0,
				(float64(d[j+3])*256.0+float64(d[j+2]))/100.0,
				(float64(d[j+5])*256.0+float64(d[j+4]))/100.0,
				(float64(d[j+7])*256.0+float64(d[j+6]))/100.0)
			j += 8
			dv.SluitemReactivePower = append(dv.SluitemReactivePower,
				(float64(d[j+1])*256.0+float64(d[j]))/100.0,
				(float64(d[j+3])*256.0+float64(d[j+2]))/100.0,
				(float64(d[j+5])*256.0+float64(d[j+4]))/100.0,
				(float64(d[j+7])*256.0+float64(d[j+6]))/100.0)
			j += 8
			dv.SluitemMaxVoltage = (float64(d[j+1])*256.0 + float64(d[j])) / 100.0
			j += 2
			s = fmt.Sprintf("%08b%08b%08b%08b", d[j], d[j+1], d[j+2], d[j+3])
			dv.SluitemPhyinfo = append(dv.SluitemPhyinfo, gopsu.String2Int32(s[28:32], 2),
				gopsu.String2Int32(s[28:32], 2),
				gopsu.String2Int32(s[24:28], 2),
				gopsu.String2Int32(s[22:24], 2),
				gopsu.String2Int32(s[19:22], 2)+1,
				gopsu.String2Int32(s[16:19], 2),
				gopsu.String2Int32(s[15:16], 2),
				gopsu.String2Int32(s[14:15], 2),
				gopsu.String2Int32(s[13:14], 2),
				gopsu.String2Int32(s[8:11], 2),
				gopsu.String2Int32(s[4:8], 2),
				gopsu.String2Int32(s[4:8], 2))
			j += 4
			dv.SluitemMaxCurrent = append(dv.SluitemMaxCurrent,
				(float64(d[j+1])*256.0+float64(d[j]))/100.0,
				(float64(d[j+3])*256.0+float64(d[j+2]))/100.0,
				(float64(d[j+5])*256.0+float64(d[j+4]))/100.0,
				(float64(d[j+7])*256.0+float64(d[j+6]))/100.0)
			j += 8
			dv.SluitemElectricity = append(dv.SluitemElectricity, float64(d[j])/10.0, float64(d[j+1])/10.0, float64(d[j+2])/10.0, float64(d[j+3])/10.0)
			j += 4
			j += 4
			svrmsg.WlstTml.WlstSluF800.View_0X23 = append(svrmsg.WlstTml.WlstSluF800.View_0X23, dv)
		}
		zm := svrmsg.WlstTml.WlstSluF800
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xf9: // 集中器主动上报
		ff := &Fwd{
			Addr:     f.Addr,
			DataType: DataTypeBytes,
			DataPT:   2000,
			DataDst:  fmt.Sprintf("wlst-slu-%d", f.Addr),
			DstType:  1,
			Tra:      tra,
			Job:      JobSend,
			DataMsg:  DoCommand(1, 1, tra, f.Addr, cid, "wlst.slu.7900", []byte{}, 5, 0),
			// DataMsg:  gopsu.Bytes2String(DoCommand(1, 1, tra, f.Addr, cid, "wlst.slu.7900", []byte{}, 5, 0), "-"),
			DataCmd: svrmsg.Head.Cmd,
		}
		lstf = append(lstf, ff)
		svrmsg.WlstTml.WlstSluF900 = &msgctl.WlstSluF900{}
		svrmsg.WlstTml.WlstSluF300 = &msgctl.WlstSlu_7300{}
		svrmsg.WlstTml.WlstSluF900.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstSluF900.AlarmType = int32(d[8])
		j := 9
		switch svrmsg.WlstTml.WlstSluF900.AlarmType {
		case 0: // 集中器告警
			m := fmt.Sprintf("%08b", d[j])
			svrmsg.WlstTml.WlstSluF900.ConcentratorData = &msgctl.WlstSlu_7300_ConcentratorData{}
			svrmsg.WlstTml.WlstSluF900.ConcentratorData.ArgsStatus = &msgctl.WlstSlu_7300_ConcentratorData_ArgsStatus{}
			svrmsg.WlstTml.WlstSluF900.ConcentratorData.HardwareStatus = &msgctl.WlstSlu_7300_ConcentratorData_HardwareStatus{}
			svrmsg.WlstTml.WlstSluF900.ConcentratorData.ArgsStatus.ConcentratorArgsError = gopsu.String2Int32(m[7:8], 2)
			svrmsg.WlstTml.WlstSluF900.ConcentratorData.ArgsStatus.SluitemArgsError = gopsu.String2Int32(m[6:7], 2)
			svrmsg.WlstTml.WlstSluF900.ConcentratorData.ArgsStatus.TurnOnoffError = gopsu.String2Int32(m[5:6], 2)
			m = fmt.Sprintf("%08b", d[j+1])
			svrmsg.WlstTml.WlstSluF900.ConcentratorData.HardwareStatus.ZigbeeError = gopsu.String2Int32(m[7:8], 2)
			svrmsg.WlstTml.WlstSluF900.ConcentratorData.HardwareStatus.CarrierError = gopsu.String2Int32(m[6:7], 2)
			svrmsg.WlstTml.WlstSluF900.ConcentratorData.HardwareStatus.FramError = gopsu.String2Int32(m[5:6], 2)
			svrmsg.WlstTml.WlstSluF900.ConcentratorData.HardwareStatus.BluetoothError = gopsu.String2Int32(m[4:5], 2)
			svrmsg.WlstTml.WlstSluF900.ConcentratorData.HardwareStatus.TimerError = gopsu.String2Int32(m[3:4], 2)
		case 1: // 控制器通讯故障
			c := int(d[j])
			j++
			for i := 0; i < c; i++ {
				svrmsg.WlstTml.WlstSluF900.ErrorCtrls = append(svrmsg.WlstTml.WlstSluF900.ErrorCtrls, int32(d[j])+int32(d[j+1])*256)
				j += 2
			}
		case 2: // 控制器状态告警
			c := int(d[j])
			j++
			for i := 0; i < c; i++ {
				csa := &msgctl.WlstSluF900_SluitemStatusAlarm{}
				csa.SluitemStatus = &msgctl.WlstSlu_7300_BaseSluitemData_SluitemStatus{}
				csa.SluitemIdx = int32(d[j]) + int32(d[j+1])*256
				csa.SluitemLoop = int32(d[j+2])
				m := fmt.Sprintf("%08b", d[j+3])
				csa.SluitemStatus.Status = gopsu.String2Int32(m[:2], 2)
				csa.SluitemStatus.Adjust = gopsu.String2Int32(m[2:3], 2)
				csa.SluitemStatus.WorkingArgs = gopsu.String2Int32(m[3:4], 2)
				csa.SluitemStatus.NoAlarm = gopsu.String2Int32(m[4:5], 2)
				csa.SluitemStatus.OffLine = gopsu.String2Int32(m[5:6], 2)
				csa.SluitemStatus.EepromError = gopsu.String2Int32(m[6:7], 2)
				csa.SluitemStatus.TemperatureSensor = gopsu.String2Int32(m[7:8], 2)
				for k := int(0); k < int(csa.SluitemLoop); k++ {
					m = fmt.Sprintf("%08b", d[j+k+4])
					ls := &msgctl.WlstSlu_7300_BaseSluitemData_LightStatus{}
					ls.PowerStatus = gopsu.String2Int32(m[:2], 2)
					ls.Leakage = gopsu.String2Int32(m[2:3], 2)
					ls.Fault = gopsu.String2Int32(m[3:6], 2)
					ls.WorkingOn = gopsu.String2Int32(m[6:8], 2)
					csa.LightStatus = append(csa.LightStatus, ls)
				}
				j += 8
				svrmsg.WlstTml.WlstSluF900.SluitemStatusAlarm = append(svrmsg.WlstTml.WlstSluF900.SluitemStatusAlarm, csa)
			}
		case 4: // 蓝牙连接申请
			var s string
			for i := 0; i < 11; i++ {
				s += strconv.FormatInt(int64(d[j+i]), 10)
			}
			j += 11
			s = ""
			for i := 0; i < 4; i++ {
				s += strconv.FormatInt(int64(d[j+i]), 10)
			}
		case 5: // 设置新域名成功
			svrmsg.WlstTml.WlstSluF900.SetDomainResult = &msgctl.WlstSluF900_SetDomainResult{}
			svrmsg.WlstTml.WlstSluF900.SetDomainResult.DomainName = int32(d[j]) + int32(d[j+1])*256
			j += 2
			for i := 0; i < 32; i++ {
				x := gopsu.ReverseString(fmt.Sprintf("%08b", d[j+i]))
				for _, v := range x {
					svrmsg.WlstTml.WlstSluF900.SetDomainResult.SetSuccess = append(svrmsg.WlstTml.WlstSluF900.SetDomainResult.SetSuccess, gopsu.String2Int32(string(v), 10))
				}
			}
		case 6: // 选测数据
			svrmsg.Head.Cmd = "wlst.slu.f300"
			f.DataCmd = svrmsg.Head.Cmd
			svrmsg.WlstTml.WlstSluF300.CmdIdx = int32(d[7])
			svrmsg.WlstTml.WlstSluF300.DataMark = 7
			x := int(d[9])
			var s string
			j := 10
			for i := 0; i < 32; i++ {
				s = fmt.Sprintf("%08b", d[j+i]) + s
			}
			s = gopsu.ReverseString(s)
			for k, v := range s {
				if v == 49 {
					svrmsg.WlstTml.WlstSluF300.SluitemAddrs = append(svrmsg.WlstTml.WlstSluF300.SluitemAddrs, int32((k+1)*(x+1)))
				}
			}
			j += 32
			c := int(d[j])
			n := c / 4
			if c%4 > 0 {
				n++
			}
			j++
			s = ""
			for i := 0; i < n; i++ {
				s = fmt.Sprintf("%08b", d[j+i]) + s
			}
			j += n
			var ctrlloop = make([]int32, 0)
			for i := len(s); i > 0; i -= 2 {
				ctrlloop = append(ctrlloop, gopsu.String2Int32(s[i-1:i], 2)+1)
			}
			for i := 0; i < c; i++ {
				cd := &msgctl.WlstSlu_7300_BaseSluitemData{}
				cd.SluitemStatus = &msgctl.WlstSlu_7300_BaseSluitemData_SluitemStatus{}
				cd.SluitemLoop = ctrlloop[i]
				s := fmt.Sprintf("%08b%08b", d[j+1], d[j])
				j += 2
				t := time.Now()
				dd := gopsu.String2Int32(s[:5], 2)
				h := gopsu.String2Int32(s[5:10], 2)
				mm := gopsu.String2Int32(s[10:16], 2)
				y := t.Year()
				m := t.Month()

				if dd > 0 && h >= 0 && h < 24 && mm < 61 && mm >= 0 {
					t1 := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:00", y, m, dd, h, mm)
					t2 := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:00", y, m, dd, t.Hour(), t.Minute())
					d1 := time.Unix(gopsu.Time2Stamp(t1), 0)
					if gopsu.Time2Stamp(t1)-gopsu.Time2Stamp(t2) < -1*60*20 {
						d1 = d1.AddDate(0, -1, 0)
					}
					cd.DateTime = d1.Unix()
				} else {
					cd.DateTime = 0
				}
				mark := fmt.Sprintf("%08b", d[j])
				j++
				cd.SluitemStatus.Status = gopsu.String2Int32(mark[:2], 2)
				cd.SluitemStatus.Adjust = gopsu.String2Int32(mark[2:3], 2)
				cd.SluitemStatus.WorkingArgs = gopsu.String2Int32(mark[3:4], 2)
				cd.SluitemStatus.NoAlarm = gopsu.String2Int32(mark[4:5], 2)
				cd.SluitemStatus.OffLine = gopsu.String2Int32(mark[5:6], 2)
				cd.SluitemStatus.EepromError = gopsu.String2Int32(mark[6:7], 2)
				cd.SluitemStatus.TemperatureSensor = gopsu.String2Int32(mark[7:8], 2)
				for k := int32(0); k < ctrlloop[i]; k++ {
					mark = fmt.Sprintf("%08b", d[j])
					j++
					ls := &msgctl.WlstSlu_7300_BaseSluitemData_LightStatus{}
					ld := &msgctl.WlstSlu_7300_BaseSluitemData_LightData{}
					ls.PowerStatus = gopsu.String2Int32(mark[:2], 2)
					ls.Leakage = gopsu.String2Int32(mark[2:3], 2)
					ls.Fault = gopsu.String2Int32(mark[3:6], 2)
					ls.WorkingOn = gopsu.String2Int32(mark[6:8], 2)
					cd.LightStatus = append(cd.LightStatus, ls)

					ld.Voltage = (float64(d[j]) + float64(d[j+1])*256) / 100.0
					j += 2
					ld.Current = (float64(d[j]) + float64(d[j+1])*256) / 100.0
					j += 2
					ld.ActivePower = (float64(d[j]) + float64(d[j+1])*256) / 10.0
					j += 2
					ld.Electricity = (float64(d[j]) + float64(d[j+1])*256) / 10.0
					j += 2
					ld.ActiveTime = float64(d[j]) + float64(d[j+1])*256 + float64(d[j+2])*256*256
					j += 3
					ld.PowerLevel = int32(d[j])
					j++
					cd.LightData = append(cd.LightData, ld)
				}
				svrmsg.WlstTml.WlstSluF300.BaseSluitemData = append(svrmsg.WlstTml.WlstSluF300.BaseSluitemData, cd)
			}
		}
		zm := svrmsg.WlstTml.WlstSluF900
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xfb: // 读取短程控制参数
		svrmsg.WlstTml.WlstSluFb00 = &msgctl.WlstSlu_7B00{}
		svrmsg.WlstTml.WlstSluFb00.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstSluFb00.SluitemIdx = int32(d[8])
		svrmsg.WlstTml.WlstSluFb00.DataCount = int32(d[9])
		if d[9] > 0 {
			if d[8] > 0 {
				dtype := fmt.Sprintf("%08b%08b%08b%08b%08b%08b%08b", d[16], d[15], d[14], d[13], d[12], d[11], d[10])
				dtype = gopsu.ReverseString(dtype)
				j := 17
				for i := 0; i < int(d[9]); i++ {
					cd := &msgctl.WlstSlu_7B00_ReadConcentratorOperationData{}
					m := fmt.Sprintf("%08b", d[j])
					cd.OperationOrder = gopsu.String2Int32(m[:4], 2)
					cd.OperationType = gopsu.String2Int32(m[4:], 2)
					m = fmt.Sprintf("%08b", d[j+1])
					for k := 7; k > 0; k-- {
						cd.WeekSet = append(cd.WeekSet, gopsu.String2Int32(string(m[k]), 10))
					}
					switch cd.OperationType {
					case 1:
						cd.TimerOrOffset = int32(d[j+2])*60 + int32(d[j+3])
					case 2:
						m := fmt.Sprintf("%016b", int32(d[j+2])+int32(d[j+3])*256)
						if m[0] == 49 {
							cd.TimerOrOffset = 0 - gopsu.String2Int32(m[1:], 2)
						} else {
							cd.TimerOrOffset = gopsu.String2Int32(m[1:], 2)
						}
					}
					if dtype[i] == 48 {
						l := d[j+4]
						h := d[j+5]
						if (h == 0 && l == 0) || (h == 0xff && l == 0xff) {
							cd.AddrType = 0
						} else {
							if h == 0xff && l < 0xff {
								cd.AddrType = 1
								cd.Addr = append(cd.Addr, int32(l))
							} else {
								if h < 0xff && l == 0xff {
									cd.AddrType = 2
									cd.Addr = append(cd.Addr, gopsu.String2Int32(fmt.Sprintf("%x", h), 10))
								} else {
									cd.AddrType = 3
									cd.Addr = append(cd.Addr, int32(h)*256+int32(l))
								}
							}
						}
					} else {
						cd.AddrType = 4
						var s string
						for i := 0; i < 32; i++ {
							s = fmt.Sprintf("%08b", d[4+j+i]) + s
						}
						s = gopsu.ReverseString(s)
						for k, v := range s {
							if v == 49 {
								cd.Addr = append(cd.Addr, int32(k+1))
							}
						}
						j += 30
					}
					cd.CmdType = int32(d[j+6])
					switch cd.CmdType {
					case 0, 1, 2, 3:
						for i := 7; i < 11; i++ {
							c := &msgctl.WlstSlu_7B00_ReadConcentratorOperationData_CmdOperation{}
							if d[j+i] == 0 {
								c.Handle = int32(d[j+6])
							} else {
								c.Handle = -1
							}
							cd.CmdMix = append(cd.CmdMix, c)
						}
					case 4:
						for i := 7; i < 11; i++ {
							c := &msgctl.WlstSlu_7B00_ReadConcentratorOperationData_CmdOperation{}
							switch d[j+i] {
							case 0:
								c.Handle = -1
							case 0x33:
								c.Handle = 0
							case 0x55:
								c.Handle = 1
							case 0xaa:
								c.Handle = 2
							case 0xcc:
								c.Handle = 3
							}
							cd.CmdMix = append(cd.CmdMix, c)
						}
					case 5:
						m := gopsu.ReverseString(fmt.Sprintf("%08b", d[j+7]))
						for i := 7; i < 11; i++ {
							c := &msgctl.WlstSlu_7B00_ReadConcentratorOperationData_CmdOperation{}
							if m[i-7] == 49 {
								c.Handle = -1
							} else {
								c.Handle = int32(d[j+8]) + 100
								c.Rate = int32(d[j+9]) * 100
							}
							cd.CmdMix = append(cd.CmdMix, c)
						}
					}
					j += 11
					svrmsg.WlstTml.WlstSluFb00.OperationData = append(svrmsg.WlstTml.WlstSluFb00.OperationData, cd)
				}
			}
		}
		zm := svrmsg.WlstTml.WlstSluFb00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xfe: // 操作控制器是否应答成功
		svrmsg.WlstTml.WlstSluFe00 = &msgctl.WlstSluFe00{}
		svrmsg.WlstTml.WlstSluFe00.CmdIdx = int32(d[7])
		if d[8] != 0xfd {
			svrmsg.WlstTml.WlstSluFe00.OperationCmd = int32(d[8])
		} else {
			svrmsg.WlstTml.WlstSluFe00.OperationCmd = 0xf4
		}
		svrmsg.WlstTml.WlstSluFe00.FaultCount = int32(d[9])
		for i := 0; i < int(d[9])*2; i += 2 {
			svrmsg.WlstTml.WlstSluFe00.SluitemIdx = append(svrmsg.WlstTml.WlstSluFe00.SluitemIdx, int32(d[10+i])+int32(d[10+i+1])*256)
		}
		zm := svrmsg.WlstTml.WlstSluFe00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xef: // 控制器复位以及参数初始化
		svrmsg.WlstTml.WlstSluEf00 = &msgctl.WlstSlu_6F00{}
		svrmsg.WlstTml.WlstSluEf00.CmdIdx = int32(d[7])
		l := d[8]
		h := d[9]
		if (h == 0 && l == 0) || (h == 0xff && l == 0xff) {
			svrmsg.WlstTml.WlstSluEf00.AddrType = 0
		} else {
			if h == 0xff && l < 0xff {
				svrmsg.WlstTml.WlstSluEf00.AddrType = 1
				svrmsg.WlstTml.WlstSluEf00.Addr = int32(l)
			} else {
				if h < 0xff && l == 0xff {
					svrmsg.WlstTml.WlstSluEf00.AddrType = 2
					svrmsg.WlstTml.WlstSluEf00.Addr = gopsu.String2Int32(fmt.Sprintf("%x", l), 10)
				} else {
					svrmsg.WlstTml.WlstSluEf00.AddrType = 3
					svrmsg.WlstTml.WlstSluEf00.Addr = int32(h)*256 + int32(l)
				}
			}
		}
		svrmsg.WlstTml.WlstSluEf00.Status = int32(d[10])
		zm := svrmsg.WlstTml.WlstSluEf00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0x86, 0x87, 0x88: // 硬件更新
	default:
		f.Ex = fmt.Sprintf("Unhandled slu protocol: %s", gopsu.Bytes2String(d, "-"))
		lstf = append(lstf, f)
		return lstf
	}

	if len(f.DataCmd) > 0 {
		f.DataMsg = CodePb2(svrmsg)
		lstf = append(lstf, f)
	}

	return lstf
}

// 处理光照度数据
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
//  tra：是否485数据1-非485,2-485
//  tmladdr: 为485数据时，父设备物理地址
// Return:
// 	lstf: 处理反馈结果
func dataAls(d []byte, ip *int64, tra byte, tmladdr int64, portlocal *int) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      tra,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}

	if !gopsu.CheckCrc16VB(d) {
		f.Ex = fmt.Sprintf("Als data validation fails")
		lstf = append(lstf, f)
		return lstf
	}
	var cmd, cid int32
	cmd = int32(d[3])
	if tmladdr == 0 {
		f.Addr = int64(d[5])
		cid = 1
	} else {
		f.Addr = tmladdr
		cid = int32(d[5])
	}
	svrmsg := initMsgCtl(fmt.Sprintf("wlst.als.%02x00", cmd), f.Addr, *ip, 1, tra, cid, portlocal)
	f.DataCmd = svrmsg.Head.Cmd
	switch cmd {
	case 0xa5: // 多光控设置地址
		svrmsg.WlstTml.WlstAlsA500 = &msgctl.WlstAlsA700{}
		svrmsg.WlstTml.WlstAlsA500.Addr = int32(d[5])
		if d[6] == 0x5a {
			svrmsg.WlstTml.WlstAlsA500.Status = 1
		} else {
			svrmsg.WlstTml.WlstAlsA500.Status = 0
		}
		zm := svrmsg.WlstTml.WlstAlsA500
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.addr", svrmsg.WlstTml.WlstAlsA500.Addr)
			jv, _ = sjson.Set(jv, "data.st", svrmsg.WlstTml.WlstAlsA500.Status)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xa6: // 旧版选测
		svrmsg.WlstTml.WlstAlsA600 = &msgctl.WlstAlsA700{}
		svrmsg.WlstTml.WlstAlsA600.Addr = 1
		s := fmt.Sprintf("%08b", d[12])
		var count int
		var a, g, c, e, x, y float64
		if s[1] == 49 {
			x = 65536.0
			y = 1000.0
		} else {
			x = 32768.0
			y = 10000.0
		}
		if s[7] == 48 {
			count++
			a = ((float64(d[4]) + float64(d[5])*256.0) / x) * y
		}
		if s[6] == 48 {
			count++
			g = ((float64(d[6]) + float64(d[7])*256.0) / x) * y
		}
		if s[5] == 48 {
			count++
			c = ((float64(d[8]) + float64(d[9])*256.0) / x) * y
		}
		if s[4] == 48 {
			count++
			e = ((float64(d[10]) + float64(d[11])*256.0) / x) * y
		}
		svrmsg.WlstTml.WlstAlsA600.Error = 4 - int32(count)
		// if count > 3 {
		// 	svrmsg.WlstTml.WlstAlsA600.Error = 0
		// } else {
		// 	svrmsg.WlstTml.WlstAlsA600.Error = 1
		// }
		if count == 0 {
			svrmsg.WlstTml.WlstAlsA600.Lux = 0
		} else {
			svrmsg.WlstTml.WlstAlsA600.Lux = (a + g + c + e) / float64(count)
		}
		zm := svrmsg.WlstTml.WlstAlsA600
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.addr", svrmsg.WlstTml.WlstAlsA600.Addr)
			jv, _ = sjson.Set(jv, "data.v", fmt.Sprintf("%.02f", svrmsg.WlstTml.WlstAlsA600.Lux))
			jv, _ = sjson.Set(jv, "data.err", svrmsg.WlstTml.WlstAlsA600.Error)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xa7: // 新版选测
		svrmsg.WlstTml.WlstAlsA700 = &msgctl.WlstAlsA700{}
		svrmsg.WlstTml.WlstAlsA700.Addr = int32(d[5])
		s := fmt.Sprintf("%08b", d[14])
		var count int
		var a, g, c, e, x, y float64
		if s[1] == 49 {
			x = 65536.0
			y = 10000.0
		} else {
			x = 32768.0
			y = 10000.0
		}
		if s[7] == 48 {
			count++
			a = ((float64(d[6]) + float64(d[7])*256.0) / x) * y
		}
		if s[6] == 48 {
			count++
			g = ((float64(d[8]) + float64(d[9])*256.0) / x) * y
		}
		if s[5] == 48 {
			count++
			c = ((float64(d[10]) + float64(d[11])*256.0) / x) * y
		}
		if s[4] == 48 {
			count++
			e = ((float64(d[12]) + float64(d[13])*256.0) / x) * y
		}
		svrmsg.WlstTml.WlstAlsA700.Error = 4 - int32(count)
		// if count > 3 {
		// 	svrmsg.WlstTml.WlstAlsA700.Error = 0
		// } else {
		// 	svrmsg.WlstTml.WlstAlsA700.Error = 1
		// }
		if count == 0 {
			svrmsg.WlstTml.WlstAlsA700.Lux = 0
		} else {
			svrmsg.WlstTml.WlstAlsA700.Lux = (a + g + c + e) / float64(count)
		}
		zm := svrmsg.WlstTml.WlstAlsA700
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.addr", svrmsg.WlstTml.WlstAlsA700.Addr)
			jv, _ = sjson.Set(jv, "data.v", fmt.Sprintf("%.02f", svrmsg.WlstTml.WlstAlsA700.Lux))
			jv, _ = sjson.Set(jv, "data.err", svrmsg.WlstTml.WlstAlsA700.Error)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xa9: // 选测3
		svrmsg.WlstTml.WlstAlsA700 = &msgctl.WlstAlsA700{}
		svrmsg.Head.Cmd = "wlst.als.a700"
		f.DataCmd = svrmsg.Head.Cmd
		svrmsg.WlstTml.WlstAlsA700.Addr = int32(d[5])
		x, _ := strconv.ParseFloat(fmt.Sprintf("%d.%d", int32(d[6])+int32(d[7])*256, int32(d[8])+int32(d[9])*256), 10)
		svrmsg.WlstTml.WlstAlsA700.Lux = x
		svrmsg.WlstTml.WlstAlsA700.Error = gopsu.String2Int32(fmt.Sprintf("%08b", d[10])[4:], 2)
		// if gopsu.String2Int32(fmt.Sprintf("%08b", d[10])[4:], 2) > 3 {
		// 	svrmsg.WlstTml.WlstAlsA700.Error = 0
		// } else {
		// 	svrmsg.WlstTml.WlstAlsA700.Error = 1
		// }
		zm := svrmsg.WlstTml.WlstAlsA700
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.addr", svrmsg.WlstTml.WlstAlsA700.Addr)
			jv, _ = sjson.Set(jv, "data.v", fmt.Sprintf("%.02f", svrmsg.WlstTml.WlstAlsA700.Lux))
			jv, _ = sjson.Set(jv, "data.err", svrmsg.WlstTml.WlstAlsA700.Error)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xb6: // 旧版模式设置
		svrmsg.WlstTml.WlstAlsB600 = &msgctl.WlstAlsA700{}
		svrmsg.WlstTml.WlstAlsB600.Addr = 1
		svrmsg.WlstTml.WlstAlsB600.Mode = int32(d[4])
		zm := svrmsg.WlstTml.WlstAlsB600
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.addr", svrmsg.WlstTml.WlstAlsB600.Addr)
			jv, _ = sjson.Set(jv, "data.mod", svrmsg.WlstTml.WlstAlsB600.Mode)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xb7: // 新版设置模式
		svrmsg.WlstTml.WlstAlsB700 = &msgctl.WlstAlsA700{}
		svrmsg.WlstTml.WlstAlsB700.Addr = int32(d[5])
		svrmsg.WlstTml.WlstAlsB700.Mode = int32(d[6])
		if d[7] == 0x5a {
			svrmsg.WlstTml.WlstAlsB700.Status = 1
		} else {
			svrmsg.WlstTml.WlstAlsB700.Status = 0
		}
		zm := svrmsg.WlstTml.WlstAlsB700
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.addr", svrmsg.WlstTml.WlstAlsB700.Addr)
			jv, _ = sjson.Set(jv, "data.mod", svrmsg.WlstTml.WlstAlsB700.Mode)
			jv, _ = sjson.Set(jv, "data.st", svrmsg.WlstTml.WlstAlsB700.Status)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xb8: // 设置上报数据时间间隔
		svrmsg.WlstTml.WlstAlsB800 = &msgctl.WlstAlsA700{}
		svrmsg.WlstTml.WlstAlsB800.Addr = int32(d[5])
		if d[6] == 0x5a {
			svrmsg.WlstTml.WlstAlsB800.Status = 1
		} else {
			svrmsg.WlstTml.WlstAlsB800.Status = 0
		}
		zm := svrmsg.WlstTml.WlstAlsB800
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.addr", svrmsg.WlstTml.WlstAlsB800.Addr)
			jv, _ = sjson.Set(jv, "data.st", svrmsg.WlstTml.WlstAlsB800.Status)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xc6: // 旧版招测工作模式
		svrmsg.WlstTml.WlstAlsC600 = &msgctl.WlstAlsA700{}
		svrmsg.WlstTml.WlstAlsC600.Addr = 1
		svrmsg.WlstTml.WlstAlsC600.Mode = int32(d[4])
		zm := svrmsg.WlstTml.WlstAlsC600
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.addr", svrmsg.WlstTml.WlstAlsC600.Addr)
			jv, _ = sjson.Set(jv, "data.mod", svrmsg.WlstTml.WlstAlsC600.Mode)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xc7: // 新版招测工作模式
		svrmsg.WlstTml.WlstAlsC700 = &msgctl.WlstAlsA700{}
		svrmsg.WlstTml.WlstAlsC700.Addr = int32(d[5])
		svrmsg.WlstTml.WlstAlsC700.Mode = int32(d[6])
		zm := svrmsg.WlstTml.WlstAlsC700
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.addr", svrmsg.WlstTml.WlstAlsC700.Addr)
			jv, _ = sjson.Set(jv, "data.mod", svrmsg.WlstTml.WlstAlsC700.Mode)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xc8: // 招测数据上报间隔
		svrmsg.WlstTml.WlstAlsC800 = &msgctl.WlstAlsA700{}
		svrmsg.WlstTml.WlstAlsC800.Addr = int32(d[5])
		svrmsg.WlstTml.WlstAlsC800.Time = int32(d[6])
		zm := svrmsg.WlstTml.WlstAlsC800
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.addr", svrmsg.WlstTml.WlstAlsC800.Addr)
			jv, _ = sjson.Set(jv, "data.t", svrmsg.WlstTml.WlstAlsC800.Time)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0xca: // 招测光照度版本
		svrmsg.WlstTml.WlstAlsCa00 = &msgctl.WlstAlsA700{}
		svrmsg.WlstTml.WlstAlsCa00.Addr = int32(d[5])
		svrmsg.WlstTml.WlstAlsCa00.Ver = string(d[6:26])
		zm := svrmsg.WlstTml.WlstAlsCa00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.addr", svrmsg.WlstTml.WlstAlsCa00.Addr)
			jv, _ = sjson.Set(jv, "data.ver", svrmsg.WlstTml.WlstAlsCa00.Ver)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	default:
		f.Ex = fmt.Sprintf("Unhandled als protocol: %s", gopsu.Bytes2String(d, "-"))
		lstf = append(lstf, f)
		return lstf
	}

	if len(f.DataCmd) > 0 {
		f.DataCmd = svrmsg.Head.Cmd
		f.DataMsg = CodePb2(svrmsg)
		lstf = append(lstf, f)
	}

	return lstf
}

// 处理电表数据
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
//  tra：是否485数据1-非485,2-485
//  tmladdr: 为485数据时，父设备物理地址
// Return:
// 	lstf: 处理反馈结果
func dataMru(d []byte, ip *int64, tra byte, tmladdr int64, portlocal *int) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      tra,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}
	// var lstf = make([]Fwd, 0)
	// defer func() {
	// 	if ex := recover(); ex != nil {
	// 		f.Src = gopsu.Bytes2String(d, "-")
	// 		f.Ex = fmt.Sprintf("%+v", errors.WithStack(ex.(error)))
	// 		lstf = append(lstf, f)
	// 	}
	// }()
	if tmladdr > 0 {
		f.Addr = tmladdr
	} else {
		var xaddr string
		for i := 6; i > 0; i-- {
			xaddr += fmt.Sprintf("%02x", d[i])
		}
		f.Addr = int64(gopsu.String2Int64(xaddr, 10))
	}
	svrmsg := initMsgCtl("", int64(f.Addr), *ip, 1, tra, 1, portlocal)
	switch d[8] {
	case 0x93, 0xd3: // 2007读地址
		f.DataCmd = "wlst.mru.9300"
		svrmsg.WlstTml.WlstMru_9300 = &msgctl.WlstMru_9100{}
		for i := 1; i < 7; i++ {
			svrmsg.WlstTml.WlstMru_9300.Addr = append(svrmsg.WlstTml.WlstMru_9300.Addr, int32(d[i]))
		}
		zm := svrmsg.WlstTml.WlstMru_9300
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			for i := 1; i < 7; i++ {
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.addr%d", i), int32(d[i]))
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x91: // 2007读数据
		f.DataCmd = "wlst.mru.9100"
		svrmsg.WlstTml.WlstMru_9100 = &msgctl.WlstMru_9100{}
		for i := 1; i < 7; i++ {
			svrmsg.WlstTml.WlstMru_9100.Addr = append(svrmsg.WlstTml.WlstMru_9100.Addr, int32(d[i]))
		}
		svrmsg.WlstTml.WlstMru_9100.MeterReadingDate = int32(d[10] - 0x33)
		switch d[12] - 0x33 {
		case 0x01:
			svrmsg.WlstTml.WlstMru_9100.MeterReadingType = 4
		case 0x15:
			svrmsg.WlstTml.WlstMru_9100.MeterReadingType = 1
		case 0x29:
			svrmsg.WlstTml.WlstMru_9100.MeterReadingType = 2
		case 0x3d:
			svrmsg.WlstTml.WlstMru_9100.MeterReadingType = 3
		case 0x0:
			svrmsg.WlstTml.WlstMru_9100.MeterReadingType = 5
		}
		mdata := float64(gopsu.Bcd2Int8(d[14]-0x33))*0.01 + float64(gopsu.Bcd2Int8(d[15]-0x33)) + float64(gopsu.Bcd2Int8(d[16]-0x33))*100 + float64(gopsu.Bcd2Int8(d[17]-0x33))*10000.0
		svrmsg.WlstTml.WlstMru_9100.MeterValue = mdata
		zm := svrmsg.WlstTml.WlstMru_9100
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.type", svrmsg.WlstTml.WlstMru_9100.MeterReadingType)
			jv, _ = sjson.Set(jv, "data.date", svrmsg.WlstTml.WlstMru_9100.MeterReadingDate)
			jv, _ = sjson.Set(jv, "data.value", svrmsg.WlstTml.WlstMru_9100.MeterValue)
			for i := 1; i < 7; i++ {
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.addr%d", i), int32(d[i]))
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x81: // 1997读数据
		f.DataCmd = "wlst.mru.9100"
		svrmsg.WlstTml.WlstMru_9100 = &msgctl.WlstMru_9100{}
		for i := 1; i < 7; i++ {
			svrmsg.WlstTml.WlstMru_9100.Addr = append(svrmsg.WlstTml.WlstMru_9100.Addr, int32(d[i]))
		}
		c := fmt.Sprintf("%02x%02x", d[10], d[11])
		switch c {
		case "43c3":
			svrmsg.WlstTml.WlstMru_9100.MeterReadingDate = 0
			svrmsg.WlstTml.WlstMru_9100.MeterReadingType = 4
		case "3417":
			svrmsg.WlstTml.WlstMru_9100.MeterReadingDate = 0
			svrmsg.WlstTml.WlstMru_9100.MeterReadingType = 1
		case "3517":
			svrmsg.WlstTml.WlstMru_9100.MeterReadingDate = 0
			svrmsg.WlstTml.WlstMru_9100.MeterReadingType = 2
		case "3617":
			svrmsg.WlstTml.WlstMru_9100.MeterReadingDate = 0
			svrmsg.WlstTml.WlstMru_9100.MeterReadingType = 3
		case "43c7":
			svrmsg.WlstTml.WlstMru_9100.MeterReadingDate = 1
			svrmsg.WlstTml.WlstMru_9100.MeterReadingType = 1
		case "43cb":
			svrmsg.WlstTml.WlstMru_9100.MeterReadingDate = 2
			svrmsg.WlstTml.WlstMru_9100.MeterReadingType = 1
		}
		mdata := float64(gopsu.Bcd2Int8(d[12]-0x33))*0.01 + float64(gopsu.Bcd2Int8(d[13]-0x33)) + float64(gopsu.Bcd2Int8(d[14]-0x33))*100 + float64(gopsu.Bcd2Int8(d[15]-0x33))*10000.0
		svrmsg.WlstTml.WlstMru_9100.MeterValue = mdata
		zm := svrmsg.WlstTml.WlstMru_9100
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.mark", c)
			jv, _ = sjson.Set(jv, "data.value", svrmsg.WlstTml.WlstMru_9100.MeterValue)
			for i := 1; i < 7; i++ {
				jv, _ = sjson.Set(jv, fmt.Sprintf("data.addr%d", i), int32(d[i]))
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x9c: // 控制器直连
		var xaddr string
		svrmsg.WlstTml.WlstSluFa00 = &msgctl.WlstSlu_9D00{}
		for i := 6; i > 0; i-- {
			xaddr += fmt.Sprintf("%02x", d[i])
		}
		svrmsg.Args.Addr[0] = gopsu.String2Int64(xaddr, 10)
		f.Addr = int64(gopsu.String2Int64(xaddr, 10))
		l := d[9]
		dd := d[10 : 10+l]
		if !gopsu.CheckCrc16VB(dd) {
			f.Ex = "vslu data validation fails"
			lstf = append(lstf, f)
			return lstf
		}
		svrmsg.Head.Tver = 3
		svrmsg.Args.Cid = int32(dd[2]) + int32(dd[3])*256
		if svrmsg.Args.Cid == 0 {
			f.Ex = "vslu cid error"
			lstf = append(lstf, f)
			return lstf
		}
		cmd := dd[4]
		switch cmd {
		case 0xd1: // 控制器读版本
			f.DataCmd = "wlst.vslu.fa00"
			f.DstType = 255
			// f.DataCmd = ""
			svrmsg.WlstTml.WlstSluFa00 = &msgctl.WlstSlu_9D00{}
			svrmsg.WlstTml.WlstSluFa00.DataMark = &msgctl.WlstSlu_1D00_DataMark{
				ReadVer: 1,
			}
			svrmsg.WlstTml.WlstSluFa00.SluitemVer = &msgctl.WlstSlu_9D00_SluitemVer{
				Ver: string(dd[5 : len(dd)-5]),
			}
			// 按老孟要求，应答心跳
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeBytes,
				DataDst:  "1",
				DstType:  1,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  SendUdpKA,
			}
			lstf = append(lstf, ffj)
		case 0xa3: // 单灯选测
			f.DataCmd = "wlst.vslu.fa00"
			svrmsg.WlstTml.WlstSluFa00 = &msgctl.WlstSlu_9D00{}
			svrmsg.WlstTml.WlstSluFa00.SetMark = &msgctl.WlstSlu_9D00_SetMark{}
			svrmsg.WlstTml.WlstSluFa00.DataMark = &msgctl.WlstSlu_1D00_DataMark{}
			svrmsg.WlstTml.WlstSluFa00.SluitemData = &msgctl.WlstSlu_9D00_SluitemData{}
			svrmsg.WlstTml.WlstSluFa00.SluitemPara = &msgctl.WlstSlu_9D00_SluitemPara{}
			svrmsg.WlstTml.WlstSluFa00.SluitemVer = &msgctl.WlstSlu_9D00_SluitemVer{}
			svrmsg.WlstTml.WlstSluFa00.SluitemSunriseset = &msgctl.WlstSlu_9D00_SluitemSunriseset{}
			svrmsg.WlstTml.WlstSluFa00.SluitemDataNew = &msgctl.WlstSlu_9D00_SluitemDataNew{}
			readMark := fmt.Sprintf("%08b%08b", dd[8], dd[7])
			if gopsu.String2Int64(readMark[3:], 2) == 0 {
				svrmsg.WlstTml.WlstSluFa00.Status = 0
				setMark := fmt.Sprintf("%08b%08b", dd[6], dd[5])
				if setMark[14:15] == "1" { // 设置时钟
					ff := &Fwd{
						DataType: DataTypeBase64,
						DataDst:  "2",
						DstType:  SockData,
						Tra:      tra,
						Job:      JobSend,
						Addr:     f.Addr,
						Src:      gopsu.Bytes2String(d, "-"),
					}
					ff.DataCmd = "wlst.vslu.f100"
					svrmsg.WlstTml.WlstSluF100 = &msgctl.WlstSluF100{
						OptMark: 0,
					}
					svrmsg.Head.Cmd = ff.DataCmd
					ff.DataMsg = CodePb2(svrmsg)
					zm := svrmsg.WlstTml.WlstSluF100
					b, ex := pb2.Marshal(zm)
					if ex == nil {
						ff.DataMQ = b
					}
					lstf = append(lstf, ff)
					svrmsg.WlstTml.WlstSluFa00.SetMark.SetTimer = 1
					svrmsg.WlstTml.WlstSluFa00.Status = 0x3a
					f.DataCmd = ""
				}
				if setMark[13:14] == "1" { // 设置参数
					ff := &Fwd{
						DataType: DataTypeBase64,
						DataDst:  "2",
						DstType:  SockData,
						Tra:      tra,
						Job:      JobSend,
						Addr:     f.Addr,
						Src:      gopsu.Bytes2String(d, "-"),
					}
					ff.DataCmd = "wlst.vslu.f200"
					svrmsg.WlstTml.WlstSluF200 = &msgctl.WlstSluF200{
						SluitemIdx:   1,
						SluitemCount: 1,
						DataMark: &msgctl.WlstSluF200_DataMark{
							SetData:       1,
							RatedPower:    1,
							Vector:        1,
							PowerOnStatus: 1,
							RunStatus:     1,
						},
						Status: 1,
					}
					svrmsg.Head.Cmd = ff.DataCmd
					ff.DataMsg = CodePb2(svrmsg)
					zm := svrmsg.WlstTml.WlstSluF200
					b, ex := pb2.Marshal(zm)
					if ex == nil {
						ff.DataMQ = b
					}
					lstf = append(lstf, ff)
					svrmsg.WlstTml.WlstSluFa00.SetMark.SetArgs = 1
					svrmsg.WlstTml.WlstSluFa00.Status = 0x3a
					f.DataCmd = ""
				}
				if setMark[11:12] == "1" { // 设置分组
					ff := &Fwd{
						DataType: DataTypeBase64,
						DataDst:  "2",
						DstType:  SockData,
						Tra:      tra,
						Job:      JobSend,
						Addr:     f.Addr,
						Src:      gopsu.Bytes2String(d, "-"),
					}
					ff.DataCmd = "wlst.vslu.f200"
					svrmsg.WlstTml.WlstSluF200 = &msgctl.WlstSluF200{
						SluitemIdx:   1,
						SluitemCount: 1,
						DataMark: &msgctl.WlstSluF200_DataMark{
							SetData: 1,
							Group:   1,
						},
						Status: 1,
					}
					svrmsg.Head.Cmd = ff.DataCmd
					ff.DataMsg = CodePb2(svrmsg)
					zm := svrmsg.WlstTml.WlstSluF200
					b, ex := pb2.Marshal(zm)
					if ex == nil {
						ff.DataMQ = b
					}
					lstf = append(lstf, ff)
					svrmsg.WlstTml.WlstSluFa00.SetMark.SetGroup = 1
					svrmsg.WlstTml.WlstSluFa00.Status = 0x3a
					f.DataCmd = ""
				}
				if setMark[9:10] == "1" { // 复位
					ff := &Fwd{
						DataType: DataTypeBase64,
						DataDst:  "2",
						DstType:  SockData,
						Tra:      tra,
						Job:      JobSend,
						Addr:     f.Addr,
						Src:      gopsu.Bytes2String(d, "-"),
					}
					ff.DataCmd = "wlst.vslu.ef00"
					svrmsg.WlstTml.WlstSluEf00 = &msgctl.WlstSlu_6F00{
						AddrType: 3,
						Addr:     1,
						ResetMark: &msgctl.WlstSlu_6F00_ResetMark{
							ResetMcu:        1,
							ResetComm:       1,
							InitMcuHardware: 1,
							InitRam:         1,
							ZeroEerom:       1,
							ZeroCount:       1,
						},
						Status: 0x5a,
					}
					svrmsg.Head.Cmd = ff.DataCmd
					ff.DataMsg = CodePb2(svrmsg)
					zm := svrmsg.WlstTml.WlstSluEf00
					b, ex := pb2.Marshal(zm)
					if ex == nil {
						ff.DataMQ = b
					}
					lstf = append(lstf, ff)
					svrmsg.WlstTml.WlstSluFa00.SetMark.SetReset = 1
					svrmsg.WlstTml.WlstSluFa00.Status = 0x3a
					f.DataCmd = ""
				}
				if setMark[6:7] == "1" { // 时间设置
					ff := &Fwd{
						DataType: DataTypeBase64,
						DataDst:  "2",
						DstType:  SockData,
						Tra:      tra,
						Job:      JobSend,
						Addr:     f.Addr,
						Src:      gopsu.Bytes2String(d, "-"),
					}
					ff.DataCmd = "wlst.vslu.fc00"
					svrmsg.WlstTml.WlstSluFc00 = &msgctl.WlstSluF400{
						CmdIdx: 2,
						Status: 0x3a}
					svrmsg.Head.Cmd = ff.DataCmd
					ff.DataMsg = CodePb2(svrmsg)
					zm := svrmsg.WlstTml.WlstSluFc00
					b, ex := pb2.Marshal(zm)
					if ex == nil {
						ff.DataMQ = b
					}
					lstf = append(lstf, ff)
					svrmsg.WlstTml.WlstSluFa00.SetMark.SetControl = 1
					svrmsg.WlstTml.WlstSluFa00.Status = 0x3a
					f.DataCmd = ""
				}
				if setMark[5:6] == "1" { // 即时控制
					ff := &Fwd{
						DataType: DataTypeBase64,
						DataDst:  "2",
						DstType:  SockData,
						Tra:      tra,
						Job:      JobSend,
						Addr:     f.Addr,
						Src:      gopsu.Bytes2String(d, "-"),
					}
					ff.DataCmd = "wlst.vslu.fc00"
					svrmsg.WlstTml.WlstSluFc00 = &msgctl.WlstSluF400{
						CmdIdx: 1,
						Status: 0x3a}
					svrmsg.Head.Cmd = ff.DataCmd
					ff.DataMsg = CodePb2(svrmsg)
					zm := svrmsg.WlstTml.WlstSluFc00
					b, ex := pb2.Marshal(zm)
					if ex == nil {
						ff.DataMQ = b
					}
					lstf = append(lstf, ff)
					svrmsg.WlstTml.WlstSluFa00.SetMark.SetControl = 1
					svrmsg.WlstTml.WlstSluFa00.Status = 0x3a
					f.DataCmd = ""
				}
			} else {
				svrmsg.WlstTml.WlstSluFa00.Status = 1
				loopCount := int(gopsu.String2Int32(readMark[:3], 2) + 1)
				svrmsg.WlstTml.WlstSluFa00.LoopCount = int32(loopCount)
				j := 9
				if readMark[15:16] == "1" { // 选测
					svrmsg.WlstTml.WlstSluFa00.DataMark.ReadData = 1
					svrmsg.WlstTml.WlstSluFa00.SluitemData.Voltage = (float64(dd[j]) + float64(dd[j+1])*256) / 100.0
					j += 2
					for i := 0; i < loopCount; i++ {
						svrmsg.WlstTml.WlstSluFa00.SluitemData.Current = append(svrmsg.WlstTml.WlstSluFa00.SluitemData.Current, (float64(dd[j])+float64(dd[j+1])*256)/100.0)
						j += 2
					}
					for i := 0; i < loopCount; i++ {
						svrmsg.WlstTml.WlstSluFa00.SluitemData.ActivePower = append(svrmsg.WlstTml.WlstSluFa00.SluitemData.ActivePower, (float64(dd[j])+float64(dd[j+1])*256)/10.0)
						j += 2
					}
					for i := 0; i < loopCount; i++ {
						svrmsg.WlstTml.WlstSluFa00.SluitemData.ReactivePower = append(svrmsg.WlstTml.WlstSluFa00.SluitemData.ReactivePower, (float64(dd[j])+float64(dd[j+1])*256)/10.0)
						j += 2
					}
					svrmsg.WlstTml.WlstSluFa00.SluitemData.MaxVoltage = (float64(dd[j]) + float64(dd[j+1])*256) / 100.0
					j += 2
					for i := 0; i < loopCount; i++ {
						svrmsg.WlstTml.WlstSluFa00.SluitemData.MaxCurrent = append(svrmsg.WlstTml.WlstSluFa00.SluitemData.MaxCurrent, (float64(dd[j])+float64(dd[j+1])*256)/100.0)
						j += 2
					}
					for i := 0; i < loopCount; i++ {
						svrmsg.WlstTml.WlstSluFa00.SluitemData.TotalElectricity = append(svrmsg.WlstTml.WlstSluFa00.SluitemData.TotalElectricity, float64(dd[j]))
						j++
					}
					for i := 0; i < loopCount; i++ {
						ls := &msgctl.WlstSlu_7300_BaseSluitemData_LightStatus{}
						s := fmt.Sprintf("%08b", dd[j])
						ls.WorkingOn = gopsu.String2Int32(s[6:8], 2)
						ls.Fault = gopsu.String2Int32(s[3:6], 2)
						ls.Leakage = gopsu.String2Int32(s[2:3], 2)
						ls.PowerStatus = gopsu.String2Int32(s[:2], 2)
						j++
						svrmsg.WlstTml.WlstSluFa00.SluitemData.LightStatus = append(svrmsg.WlstTml.WlstSluFa00.SluitemData.LightStatus, ls)
					}
					svrmsg.WlstTml.WlstSluFa00.SluitemData.LeakageCurrent = float64(dd[j]) / 100.0
					j++
					s := fmt.Sprintf("%08b", dd[j])
					x, _ := strconv.ParseInt(s[1:], 2, 0)
					if s[0] == 49 {
						svrmsg.WlstTml.WlstSluFa00.SluitemData.Temperature = 0 - int32(x)
					} else {
						svrmsg.WlstTml.WlstSluFa00.SluitemData.Temperature = int32(x)
					}
					j++
					s = fmt.Sprintf("%08b", dd[j])
					svrmsg.WlstTml.WlstSluFa00.SluitemData.SluitemStatus = &msgctl.WlstSlu_7300_BaseSluitemData_SluitemStatus{}
					svrmsg.WlstTml.WlstSluFa00.SluitemData.SluitemStatus.TemperatureSensor = gopsu.String2Int32(s[7:8], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemData.SluitemStatus.EepromError = gopsu.String2Int32(s[6:7], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemData.SluitemStatus.OffLine = gopsu.String2Int32(s[5:6], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemData.SluitemStatus.NoAlarm = gopsu.String2Int32(s[4:5], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemData.SluitemStatus.WorkingArgs = gopsu.String2Int32(s[3:4], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemData.SluitemStatus.Adjust = gopsu.String2Int32(s[2:3], 2)
					j++
					svrmsg.WlstTml.WlstSluFa00.SluitemData.TimerError = int32(dd[j])
					j++
					svrmsg.WlstTml.WlstSluFa00.SluitemData.ResetCount = int32(dd[j])
					j += 6
				}
				if readMark[14:15] == "1" { // 读取时钟
					svrmsg.WlstTml.WlstSluFa00.DataMark.ReadTimer = 1
					svrmsg.WlstTml.WlstSluFa00.SluitemTime = gopsu.Time2Stamp(fmt.Sprintf("20%02d-%02d-%02d %02d:%02d:%02d", dd[j], dd[j+1], dd[j+2], dd[j+3], dd[j+4], dd[j+5]))
					j += 6
				}
				if readMark[13:14] == "1" { // 读取运行参数
					svrmsg.WlstTml.WlstSluFa00.DataMark.ReadArgs = 1
					x, _ := strconv.ParseFloat(fmt.Sprintf("%d.%02d", dd[j], int(dd[j+1])), 10)
					svrmsg.WlstTml.WlstSluFa00.SluitemPara.Longitude = x
					j += 2
					x, _ = strconv.ParseFloat(fmt.Sprintf("%d.%02d", dd[j], int(dd[j+1])), 10)
					svrmsg.WlstTml.WlstSluFa00.SluitemPara.Latitude = x
					j += 2
					svrmsg.WlstTml.WlstSluFa00.SluitemPara.DomainName = int32(dd[j]) + int32(dd[j+1])*256
					j += 2
					s := fmt.Sprintf("%08b", dd[j])
					y, _ := strconv.ParseInt(s[:4], 2, 0)
					if y == 5 {
						svrmsg.WlstTml.WlstSluFa00.SluitemPara.SluitemEnableAlarm = 1
					} else {
						svrmsg.WlstTml.WlstSluFa00.SluitemPara.SluitemEnableAlarm = 0
					}
					y, _ = strconv.ParseInt(s[4:], 2, 0)
					if y == 5 {
						svrmsg.WlstTml.WlstSluFa00.SluitemPara.SluitemStatus = 1
					} else {
						svrmsg.WlstTml.WlstSluFa00.SluitemPara.SluitemStatus = 0
					}
					j++
					s = fmt.Sprintf("%08b", dd[j])
					for i := 0; i < loopCount; i++ {
						if s[8-(i+1):8-i] == "0" {
							svrmsg.WlstTml.WlstSluFa00.SluitemPara.SluitemPowerTurnon = append(svrmsg.WlstTml.WlstSluFa00.SluitemPara.SluitemPowerTurnon, 1)
						} else {
							svrmsg.WlstTml.WlstSluFa00.SluitemPara.SluitemPowerTurnon = append(svrmsg.WlstTml.WlstSluFa00.SluitemPara.SluitemPowerTurnon, 0)
						}
					}
					j++
					s = fmt.Sprintf("%08b", dd[j])
					for i := 0; i < loopCount; i++ {
						y, _ = strconv.ParseInt(s[8-(i*2+2):8-i*2], 2, 0)
						svrmsg.WlstTml.WlstSluFa00.SluitemPara.SluitemVector = append(svrmsg.WlstTml.WlstSluFa00.SluitemPara.SluitemVector, int32(y))
					}
					j++
					s = fmt.Sprintf("%08b%08b", dd[j+1], dd[j])
					for i := 0; i < loopCount; i++ {
						y, _ = strconv.ParseInt(s[16-(i*4+4):16-i*4], 2, 0)
						svrmsg.WlstTml.WlstSluFa00.SluitemPara.RatedPower = append(svrmsg.WlstTml.WlstSluFa00.SluitemPara.RatedPower, int32(y))
					}
					j += 2
					s = fmt.Sprintf("%08b", dd[j])
					svrmsg.WlstTml.WlstSluFa00.SluitemPara.UplinkReply = gopsu.String2Int32(s[:1], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemPara.UplinkTimer = gopsu.String2Int32(s[1:], 2) * 5
					if svrmsg.WlstTml.WlstSluFa00.SluitemPara.UplinkTimer == 0 {
						svrmsg.WlstTml.WlstSluFa00.SluitemPara.UplinkTimer = 30
					}
					j += 1
				}
				if readMark[11:12] == "1" { // 读取组地址
					svrmsg.WlstTml.WlstSluFa00.DataMark.ReadGroup = 1
					svrmsg.WlstTml.WlstSluFa00.SluitemGroup = append(svrmsg.WlstTml.WlstSluFa00.SluitemGroup, int32(dd[j]), int32(dd[j+1]), int32(dd[j+2]), int32(dd[j+3]), int32(dd[j+4]))
					j += 5
				}
				if readMark[10:11] == "1" { // 读取版本
					svrmsg.WlstTml.WlstSluFa00.DataMark.ReadVer = 1
					s := fmt.Sprintf("%08b%08b", dd[j+1], dd[j])
					svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemLoop = gopsu.String2Int32(s[13:16], 2) + 1
					svrmsg.WlstTml.WlstSluFa00.SluitemVer.EnergySaving = gopsu.String2Int32(s[10:13], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemVer.ElectricLeakageModule = gopsu.String2Int32(s[9:10], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemVer.TemperatureModule = gopsu.String2Int32(s[8:9], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemVer.TimerModule = gopsu.String2Int32(s[7:8], 2)
					x, _ := strconv.ParseInt(s[:4], 2, 0)
					switch x {
					case 0:
						svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "unknow"
					case 1:
						svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2190"
					case 2:
						svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2090j"
					case 3:
						svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj5090"
					case 4:
						svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2090k"
					case 5:
						svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2290"
					case 6:
						svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2080c"
					case 8:
						svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2080d"
					case 9:
						svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj4090b"
					case 10:
						svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2090l"
					case 12:
						svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2090m"
					case 14:
						svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj4090a"
					default:
						svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "unknow"
					}
					j += 2
					svrmsg.WlstTml.WlstSluFa00.SluitemVer.Ver = string(dd[j : j+20])
					j += 20
				}
				if readMark[9:10] == "1" { // 读取当天日出日落
					svrmsg.WlstTml.WlstSluFa00.DataMark.ReadSunriseset = 1
					svrmsg.WlstTml.WlstSluFa00.SluitemSunriseset.Sunrise = int32(dd[j])*60 + int32(dd[j+1])
					j += 2
					svrmsg.WlstTml.WlstSluFa00.SluitemSunriseset.Sunset = int32(dd[j])*60 + int32(dd[j+1])
					j += 2
				}
				if readMark[6:7] == "1" { // 读取本地参数（新）
					svrmsg.WlstTml.WlstSluFa00.DataMark.ReadTimetable = 1
					s := fmt.Sprintf("%08b", dd[j])        // 后续条数
					c := int(gopsu.String2Int32(s[2:], 2)) // 条数
					// 加入是否有后续数据返回
					if s[0] == 49 {
						svrmsg.WlstTml.WlstSluFa00.DataContinue = 1
					}
					j++
					mtype := fmt.Sprintf("%08b%08b%08b%08b", dd[j+3], dd[j+2], dd[j+1], dd[j]) // 数据类型4字节
					j += 4
					for i := 0; i < c; i++ {
						cr := &msgctl.WlstSlu_9D00_SluitemRuntime{}
						cr.DataType = gopsu.String2Int32(mtype[32-i-1:32-1], 2)
						m := fmt.Sprintf("%08b", dd[j]) // 操作字节
						cr.OutputType = gopsu.String2Int32(m[4:], 2)
						cr.OperateType = gopsu.String2Int32(m[:4], 2)
						m = fmt.Sprintf("%08b", dd[j+1]) // 时间字节周
						for k := 0; k < 7; k++ {
							cr.DateEnable = append(cr.DateEnable, gopsu.String2Int32(m[7-k:8-k], 2))
						}
						switch cr.OperateType {
						case 1:
							cr.OperateTime = int32(dd[j+2])*60 + int32(dd[j+3]) // 时间字节时分
						case 2:
							m = fmt.Sprintf("%016b", int32(dd[j+2])+int32(dd[j+3])*256)
							y := gopsu.String2Int32(m[1:], 2)
							if m[0] == 49 {
								cr.OperateOffset = 0 - int32(y)
							} else {
								cr.OperateOffset = int32(y)
							}
						}
						m = fmt.Sprintf("%08b", dd[j+4]) // 动作字节
						n := fmt.Sprintf("%08b", dd[j+5])
						switch cr.OutputType {
						case 0: // 继电器输出
							y, _ := strconv.ParseInt(m[4:], 2, 0)
							x, _ := strconv.ParseInt(m[:4], 2, 0)
							cr.RelayOperate = append(cr.RelayOperate, int32(y), int32(x))
							y, _ = strconv.ParseInt(n[4:], 2, 0)
							x, _ = strconv.ParseInt(n[:4], 2, 0)
							cr.RelayOperate = append(cr.RelayOperate, int32(y), int32(x))
						case 1: // 调光
							cr.PwmLoop = append(cr.PwmLoop, gopsu.String2Int32(m[7:8], 10), gopsu.String2Int32(m[6:7], 10), gopsu.String2Int32(m[5:6], 10), gopsu.String2Int32(m[4:5], 10))
							x, _ := strconv.ParseInt(m[:4], 2, 0)
							y, _ := strconv.ParseInt(n[:4], 2, 0)
							cr.PwmPower = int32(x)*10 + int32(y)
							z, _ := strconv.ParseInt(n[4:], 2, 0)
							cr.PwmBaudrate = int32(z) * 100
						}
						j += 6
						svrmsg.WlstTml.WlstSluFa00.SluitemRuntime = append(svrmsg.WlstTml.WlstSluFa00.SluitemRuntime, cr)
					}
				}
				if readMark[5:6] == "1" { // 选测（新）
					svrmsg.WlstTml.WlstSluFa00.SluitemIdx = f.Addr
					svrmsg.WlstTml.WlstSluFa00.DataMark.ReadCtrldata = 1
					for i := 0; i < loopCount; i++ {
						svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.Voltage = append(svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.Voltage, (float64(dd[j])+float64(dd[j+1])*256)/100.0)
						j += 2
					}
					for i := 0; i < loopCount; i++ {
						svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.Current = append(svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.Current, (float64(dd[j])+float64(dd[j+1])*256)/100.0)
						j += 2
					}
					for i := 0; i < loopCount; i++ {
						svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.ActivePower = append(svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.ActivePower, (float64(dd[j])+float64(dd[j+1])*256)/10.0)
						j += 2
					}
					for i := 0; i < loopCount; i++ {
						svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.TotalElectricity = append(svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.TotalElectricity, (float64(dd[j])+float64(dd[j+1])*256)/10.0)
						j += 2
					}
					for i := 0; i < loopCount; i++ {
						svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.RunTime = append(svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.RunTime, int32(dd[j])+int32(dd[j+1])*256+int32(dd[j+2])*256*256)
						j += 3
					}
					for i := 0; i < loopCount; i++ {
						s := fmt.Sprintf("%08b", dd[j])
						ls := &msgctl.WlstSlu_7300_BaseSluitemData_LightStatus{}
						ls.WorkingOn = gopsu.String2Int32(s[6:8], 2)
						ls.Fault = gopsu.String2Int32(s[3:6], 2)
						ls.Leakage = gopsu.String2Int32(s[2:3], 2)
						ls.PowerStatus = gopsu.String2Int32(s[:2], 2)
						j++
						svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.LightStatus = append(svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.LightStatus, ls)
					}
					svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.LeakageCurrent = float64(dd[j]) / 100.0
					j++
					s := fmt.Sprintf("%08b", dd[j])
					svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.SluitemStatus = &msgctl.WlstSlu_7300_BaseSluitemData_SluitemStatus{}
					svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.SluitemStatus.TemperatureSensor = gopsu.String2Int32(s[7:8], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.SluitemStatus.EepromError = gopsu.String2Int32(s[6:7], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.SluitemStatus.OffLine = gopsu.String2Int32(s[5:6], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.SluitemStatus.NoAlarm = gopsu.String2Int32(s[4:5], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.SluitemStatus.WorkingArgs = gopsu.String2Int32(s[3:4], 2)
					svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.SluitemStatus.Adjust = gopsu.String2Int32(s[2:3], 2)
					j++
					svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.TimerError = int32(dd[j])
					j++
					svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.ResetCount = int32(dd[j])
					j++
					s = fmt.Sprintf("%08b", dd[j])
					svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.Phase = gopsu.String2Int32(s[4:], 2)
					j++
					x1 := fmt.Sprintf("%08b%08b", dd[j+1], dd[j])
					x2 := fmt.Sprintf("%08b%08b", dd[j+3], dd[j+2])
					svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.EnergySaving = append(svrmsg.WlstTml.WlstSluFa00.SluitemDataNew.EnergySaving,
						gopsu.String2Int32(fmt.Sprintf("%d%d", gopsu.String2Int32(x1[12:], 2), gopsu.String2Int32(x2[12:], 2)), 10),
						gopsu.String2Int32(fmt.Sprintf("%d%d", gopsu.String2Int32(x1[8:12], 2), gopsu.String2Int32(x2[8:12], 2)), 10),
						gopsu.String2Int32(fmt.Sprintf("%d%d", gopsu.String2Int32(x1[4:8], 2), gopsu.String2Int32(x2[4:8], 2)), 10),
						gopsu.String2Int32(fmt.Sprintf("%d%d", gopsu.String2Int32(x1[:4], 2), gopsu.String2Int32(x2[:4], 2)), 10))
					j += 4
					j += 3
				}
			}
			zm := svrmsg.WlstTml.WlstSluFa00
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				f.DataMQ = b
			}
		case 0xaf: // 读取地址信息
			f.DataCmd = "wlst.vslu.fa00"
			svrmsg.WlstTml.WlstSluFa00.DataMark = &msgctl.WlstSlu_1D00_DataMark{}
			svrmsg.WlstTml.WlstSluFa00.SluitemVer = &msgctl.WlstSlu_9D00_SluitemVer{}
			svrmsg.WlstTml.WlstSluFa00.DataMark.ReadVer = 1
			s := fmt.Sprintf("%08b%08b", dd[10], dd[9])
			svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemLoop = gopsu.String2Int32(s[13:16], 2)
			svrmsg.WlstTml.WlstSluFa00.SluitemVer.EnergySaving = gopsu.String2Int32(s[10:13], 2)
			svrmsg.WlstTml.WlstSluFa00.SluitemVer.ElectricLeakageModule = gopsu.String2Int32(s[9:10], 2)
			svrmsg.WlstTml.WlstSluFa00.SluitemVer.TemperatureModule = gopsu.String2Int32(s[8:9], 2)
			svrmsg.WlstTml.WlstSluFa00.SluitemVer.TimerModule = gopsu.String2Int32(s[7:8], 2)
			x, _ := strconv.ParseInt(s[:4], 2, 0)
			switch x {
			case 0:
				svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "unknow"
			case 1:
				svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2190"
			case 2:
				svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2090j"
			case 3:
				svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj5090"
			case 4:
				svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2090k"
			case 5:
				svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2290"
			case 6:
				svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2080c"
			case 8:
				svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2080d"
			case 9:
				svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj4090b"
			case 10:
				svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2090l"
			case 12:
				svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj2090m"
			case 14:
				svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "wj4090a"
			default:
				svrmsg.WlstTml.WlstSluFa00.SluitemVer.SluitemType = "unknow"
			}
			svrmsg.WlstTml.WlstSluFa00.Status = 1
			// 按老孟要求，应答心跳
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "1",
				DstType:  DataTypeBytes,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  SendUdpKA,
			}
			lstf = append(lstf, ffj)

			zm := svrmsg.WlstTml.WlstSluFa00
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				f.DataMQ = b
			}
		case 0xb9: // 控制器主报（仅NB）
			f.DataCmd = "wlst.vslu.b900"
			svrmsg.WlstTml.WlstSluB900 = &msgctl.WlstSlu_3900{}
			svrmsg.WlstTml.WlstSluB900.ModelInfo = &msgctl.WlstSlu_3900_ModelInfo{}
			svrmsg.WlstTml.WlstSluB900.SluitemStatus = &msgctl.WlstSlu_3900_SluitemStatus{}
			svrmsg.WlstTml.WlstSluB900.TimeFault = &msgctl.WlstSlu_3900_TimeFault{}
			svrmsg.WlstTml.WlstSluB900.SluitemPara = &msgctl.WlstSlu_3900_SluitemPara{}
			// 序号
			svrmsg.WlstTml.WlstSluB900.CmdIdx = int32(d[5])

			// 型号
			mi := &msgctl.WlstSlu_3900_ModelInfo{}
			j := 16
			m := fmt.Sprintf("%08b%08b", d[j+1], d[j])
			j += 2
			mi.Model = gopsu.String2Int32(m[:4], 2)
			switch mi.Model {
			case 0:
				mi.SluitemType = "unknow"
			case 1:
				mi.SluitemType = "wj2190"
			case 2:
				mi.SluitemType = "wj2090j"
			case 3:
				mi.SluitemType = "wj5090"
			case 4:
				mi.SluitemType = "wj2090k"
			case 5:
				mi.SluitemType = "wj2290"
			case 6:
				mi.SluitemType = "wj2080c"
			case 8:
				mi.SluitemType = "wj2080d"
			case 9:
				mi.SluitemType = "wj4090b"
			case 10:
				mi.SluitemType = "wj2090l"
			case 12:
				mi.SluitemType = "wj2090m"
			case 14:
				mi.SluitemType = "wj4090a"
			default:
				mi.SluitemType = "unknow"
			}
			mi.HasTimer = gopsu.String2Int32(m[7:8], 2)
			mi.HasTemperature = gopsu.String2Int32(m[8:9], 2)
			mi.HasLeakage = gopsu.String2Int32(m[9:10], 2)
			mi.PowerSaving = gopsu.String2Int32(m[10:13], 2)
			mi.SluitemLoop = gopsu.String2Int32(m[13:16], 2) + 1
			svrmsg.WlstTml.WlstSluB900.ModelInfo = mi

			// 回路数据（电压、电流、有功、无功、视在、电量、运行时间、灯状态）
			cbd := &msgctl.WlstSlu_3900{}
			for k := 0; k < 4; k++ {
				ld := &msgctl.WlstSlu_3900_LightData{}
				ls := &msgctl.WlstSlu_3900_LightStatus{}

				ld.Voltage = (float64(d[j+2*k]) + float64(d[j+1+2*k])*256) / 100
				ld.Current = (float64(d[j+8+2*k]) + float64(d[j+9+2*k])*256) / 100
				ld.ActivePower = (float64(d[j+16+2*k]) + float64(d[j+17+2*k])*256) / 10
				ld.ReactivePower = (float64(d[j+24+2*k]) + float64(d[j+25+2*k])*256) / 10
				ld.ApparentPower = (float64(d[j+32+2*k]) + float64(d[j+33+2*k])*256) / 10
				ld.Electricity = (float64(d[j+40+2*k]) + float64(d[j+41+2*k])*256) / 10
				ld.ActiveTime = float64(d[j+48+3*k]) + float64(d[j+49+3*k])*256 + float64(d[j+50+3*k])*256*256

				m = fmt.Sprintf("%08b", d[j+60+k])
				ls.Leakage = gopsu.String2Int32(m[2:3], 2)
				ls.Fault = gopsu.String2Int32(m[3:6], 2)
				ls.WorkingOn = gopsu.String2Int32(m[6:8], 2)

				ld.LightStatus = ls
				cbd.LightData = append(cbd.LightData, ld)
			}
			j += 64

			// 漏电流 控制器状态 时钟故障 自复位次数
			svrmsg.WlstTml.WlstSluB900.LeakageCurrent = float64(d[j]) / 100
			j += 1
			m = fmt.Sprintf("%08b", d[j])
			svrmsg.WlstTml.WlstSluB900.SluitemStatus.FlashFault = gopsu.String2Int32(m[6:7], 2)
			svrmsg.WlstTml.WlstSluB900.SluitemStatus.EnableAlarm = gopsu.String2Int32(m[4:5], 2)
			j += 1
			svrmsg.WlstTml.WlstSluB900.TimeFault.ClockFault = gopsu.String2Int32(m[7:8], 2)
			svrmsg.WlstTml.WlstSluB900.TimeFault.ClockOutFault = gopsu.String2Int32(m[6:7], 2)
			svrmsg.WlstTml.WlstSluB900.TimeFault.ClockOutAlarm = gopsu.String2Int32(m[5:6], 2)
			j += 1
			svrmsg.WlstTml.WlstSluB900.ResetCount = int32(d[j])
			j += 1

			// 回路数据（节能档位）
			for k, _ := range cbd.LightData {
				cbd.LightData[k].PowerLevel = int32(d[j+k])
			}
			j += 4

			// 时间
			t := fmt.Sprintf("20%02d-%02d-%02d %02d:%02d:%02d", int32(d[j]), int32(d[j+1]), int32(d[j+2]), int32(d[j+3]), int32(d[j+4]), int32(d[j+5]))
			svrmsg.WlstTml.WlstSluB900.DateTime = gopsu.Time2Stamp(t)
			j += 6

			// 运行参数(经纬度 投停运)
			svrmsg.WlstTml.WlstSluB900.SluitemPara.Longitude = float64(d[j]) + float64(d[j+1])/100 + float64(d[j+2])/10000 + float64(d[j+3])/1000000
			j += 4
			svrmsg.WlstTml.WlstSluB900.SluitemPara.Latitude = float64(d[j]) + float64(d[j+1])/100 + float64(d[j+2])/10000 + float64(d[j+3])/1000000
			j += 4
			m = fmt.Sprintf("%02d", d[j])
			if gopsu.String2Int32(m[:1], 2) == 5 {
				svrmsg.WlstTml.WlstSluB900.SluitemPara.HasEnableAlarm = 0
			} else if gopsu.String2Int32(m[:1], 2) == 10 {
				svrmsg.WlstTml.WlstSluB900.SluitemPara.HasEnableAlarm = 1
			}
			if gopsu.String2Int32(m[1:2], 2) == 5 {
				svrmsg.WlstTml.WlstSluB900.SluitemPara.IsRunning = 0
			} else if gopsu.String2Int32(m[1:2], 2) == 10 {
				svrmsg.WlstTml.WlstSluB900.SluitemPara.IsRunning = 1
			}
			j += 1

			// 回路数据（控制器上电开灯 额定功率）
			m = fmt.Sprintf("%08b", d[j])
			for k, _ := range m[4:8] {
				cbd.LightData[k].SluitemPowerTurnon = gopsu.String2Int32(m[7-k:8-k], 2)
			}
			j += 1
			for k, _ := range cbd.LightData {
				cbd.LightData[k].RatedPower = int32(d[j+2*k]) + int32(d[j+1+2*k])*256
			}
			j += 8

			// 运行参数(主报参数)
			m = fmt.Sprintf("%08b", d[j])
			repflg := gopsu.String2Int32(m[:1], 2)
			svrmsg.WlstTml.WlstSluB900.SluitemPara.AlarmInterval = gopsu.String2Int32(m[1:], 2) * 5
			if svrmsg.WlstTml.WlstSluB900.SluitemPara.AlarmInterval == 0 {
				svrmsg.WlstTml.WlstSluB900.SluitemPara.AlarmInterval = 30
			}
			j += 1

			// 调试信息
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			if gopsu.String2Int64(m[:1], 2) == 0 {
				svrmsg.WlstTml.WlstSluB900.Rsrp = gopsu.String2Int64(m[1:], 2)
			} else {
				svrmsg.WlstTml.WlstSluB900.Rsrp = 0 - gopsu.String2Int64(m[1:], 2)
			}
			j += 4
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			if gopsu.String2Int64(m[:1], 2) == 0 {
				svrmsg.WlstTml.WlstSluB900.Rssi = gopsu.String2Int64(m[1:], 2)
			} else {
				svrmsg.WlstTml.WlstSluB900.Rssi = 0 - gopsu.String2Int64(m[1:], 2)
			}
			j += 4
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			svrmsg.WlstTml.WlstSluB900.Snr = gopsu.String2Int64(m, 2)
			j += 4
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			svrmsg.WlstTml.WlstSluB900.Pci = gopsu.String2Int64(m, 2)
			j += 4
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			if gopsu.String2Int64(m[:1], 2) == 0 {
				svrmsg.WlstTml.WlstSluB900.Rsrq = gopsu.String2Int64(m[1:], 2)
			} else {
				svrmsg.WlstTml.WlstSluB900.Rsrq = 0 - gopsu.String2Int64(m[1:], 2)
			}
			j += 4
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			if gopsu.String2Int64(m[:1], 2) == 0 {
				svrmsg.WlstTml.WlstSluB900.Txpower = gopsu.String2Int64(m[1:], 2)
			} else {
				svrmsg.WlstTml.WlstSluB900.Txpower = 0 - gopsu.String2Int64(m[1:], 2)
			}
			j += 4
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			svrmsg.WlstTml.WlstSluB900.Earfcn = gopsu.String2Int64(m, 2)
			j += 4
			svrmsg.WlstTml.WlstSluB900.Ecl = int32(d[j])
			j += 1
			svrmsg.WlstTml.WlstSluB900.Csq = int32(d[j])
			j += 1
			svrmsg.WlstTml.WlstSluB900.Reson = int32(d[j])
			j += 1
			svrmsg.WlstTml.WlstSluB900.Retry = int32(d[j]) + int32(d[j+1])*256
			j += 2

			// 日出日落时间
			svrmsg.WlstTml.WlstSluB900.Sunrise = int32(d[j])*60 + int32(d[j+1])
			j += 2
			svrmsg.WlstTml.WlstSluB900.Sunset = int32(d[j])*60 + int32(d[j+1])
			j += 2

			svrmsg.WlstTml.WlstSluB900.LightData = cbd.LightData
			zm := svrmsg.WlstTml.WlstSluB900
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				f.DataMQ = b
			}
			if repflg == 1 && svrmsg.WlstTml.WlstSluB900.Reson != 0 {
				sendstr := DoCommand(1, 1, 1, f.Addr, 1, "wlst.vslu.3900", []byte{d[6]}, 1, 1)
				ff := &Fwd{
					Addr:     f.Addr,
					DataCmd:  "wlst.vslu.3900",
					DataType: DataTypeBytes,
					DataPT:   1000,
					DataDst:  fmt.Sprintf("wlst-nbslu-%d", f.Addr),
					DstType:  SockTml,
					Tra:      TraDirect,
					Job:      JobSend,
					DataMsg:  sendstr,
				}
				//ff.DstIMEI=
				//println(fmt.Sprintf("%+v", ff))
				lstf = append(lstf, ff)
			}
		default:
			f.Ex = "Unhandled vslu data"
			lstf = append(lstf, f)
			return lstf
		}
	default:
		f.Ex = "Unhandled ahhf data"
		lstf = append(lstf, f)
		return lstf
	}

	if len(f.DataCmd) > 0 {
		svrmsg.Head.Cmd = f.DataCmd
		f.DataMsg = CodePb2(svrmsg)
		lstf = append(lstf, f)
	}

	return lstf
}

// 处理模块通信数据
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
//  tra：是否485数据1-非485,2-485
//  tmladdr: 为485数据时，父设备物理地址
// Return:
// 	lstf: 处理反馈结果
func dataCom(d []byte, ip *int64, portlocal, portremote *int) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      TraDirect,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}
	if !gopsu.CheckCrc16VB(d) {
		f.Ex = fmt.Sprintf("Com data validation fails")
		lstf = append(lstf, f)
		return lstf
	}
	f.Addr = gopsu.String2Int64(string(d[4:15]), 10)
	svrmsg := initMsgCtl(fmt.Sprintf("wlst.com.3e%02x", d[15]), f.Addr, *ip, 1, 1, 1, portlocal)
	f.DataCmd = svrmsg.Head.Cmd

	switch d[15] {
	case 0x84: // 心跳应答
		svrmsg.WlstCom_3E84 = &msgctl.WlstCom_3E84{}
		j := 4
		svrmsg.WlstCom_3E84.Addr = string(d[j : j+11])
		j += 11
		j++
		svrmsg.WlstCom_3E84.Signal = int32(d[j])
		j++
		svrmsg.WlstCom_3E84.DisconnCount = int32(d[j]) + int32(d[j+1])*256
		j += 2
		svrmsg.WlstCom_3E84.ResetCount = int32(d[j])
		j++
		j += 5
		l := int(d[2]) + int(d[3])*256
		switch l {
		case 22: // 含网络模式
			svrmsg.WlstCom_3E84.NetType = int32(d[j])
			j++
		}
		f.Remark, _ = sjson.Set(f.Remark, "net_type", svrmsg.WlstCom_3E84.NetType)
		f.Remark, _ = sjson.Set(f.Remark, "signal", svrmsg.WlstCom_3E84.Signal)

		ff := &Fwd{}
		ff.DataCmd = "wlst.com.3e04"
		ff.Tra = TraDirect
		ff.DataType = DataTypeBytes
		ff.DataPT = 500
		// ff.Addr = gopsu.String2Int64(fmt.Sprintf("%d%d", *ip, *portremote), 10)
		// ff.DataDst = fmt.Sprintf("wlst-com-%d%d", *ip, *portremote)
		ff.DstType = SockTml
		ff.Job = JobSend
		ff.DataMsg = []byte{0x3e, 0x3c, 0x04, d[24]}
		// ff.DataMsg = fmt.Sprintf("3e-3c-04-%02x", d[24])
		lstf = append(lstf, ff)

	case 0x85: // 上电对时
		t := time.Now()
		s := fmt.Sprintf("%06b%04b%05b%05b%06b%06b", t.Year()-2014, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
		dd := make([]byte, 0, 4)
		for i := 1; i <= 4; i++ {
			dd = append(dd, gopsu.String2Int8(s[32-8*i:32-8*(i-1)], 2))
		}
		f.DataCmd = "wlst.com.3e05"
		f.DataType = DataTypeBytes
		f.DataPT = 500
		f.DstType = SockTml
		f.Tra = TraDirect
		f.Job = JobSend
		f.DataMsg = DoCommand(1, 1, 1, f.Addr, 1, "wlst.com.3e05", dd, 5, 0)
		// f.DataMsg = gopsu.Bytes2String(DoCommand(1, 1, 1, f.Addr, 1, "wlst.com.3e05", dd, 5, 0), "-")
	case 0x81: // 新参数选测
		svrmsg.WlstCom_3E81 = &msgctl.WlstCom_3E02{}
		svrmsg.WlstCom_3E81.Operators = &msgctl.WlstCom_3E02_Group01{}
		svrmsg.WlstCom_3E81.Channel = &msgctl.WlstCom_3E02_Group02{}
		svrmsg.WlstCom_3E81.Interface = &msgctl.WlstCom_3E02_Group03{}
		svrmsg.WlstCom_3E81.Sms = &msgctl.WlstCom_3E02_Group04{}
		svrmsg.WlstCom_3E81.Address = &msgctl.WlstCom_3E02_Group05{}
		svrmsg.WlstCom_3E81.Status = &msgctl.WlstCom_3E02_Group06{}
		switch d[16] {
		case 0x55:
			svrmsg.WlstCom_3E81.Addr = ""
			svrmsg.WlstCom_3E81.GroupMark = int32(d[17])
			s := fmt.Sprintf("%08b", d[17])
			j := 18
			for _, v := range d[j : j+strings.Count(s, "1")*2] {
				svrmsg.WlstCom_3E81.ArgsMark = append(svrmsg.WlstCom_3E81.ArgsMark, int32(v))
			}
			j += strings.Count(s, "1") * 2
			x := 0
			if s[7] == 49 { // 运营商参数
				m := fmt.Sprintf("%08b", svrmsg.WlstCom_3E81.ArgsMark[x])
				x += 2
				if m[7] == 49 { // apn
					svrmsg.WlstCom_3E81.Operators.Apn = string(d[j : j+32])
					j += 32
				}
				if m[6] == 49 { // 用户名
					svrmsg.WlstCom_3E81.Operators.User = string(d[j : j+32])
					j += 32
				}
				if m[5] == 49 { // 密码
					svrmsg.WlstCom_3E81.Operators.Pwd = string(d[j : j+32])
					j += 32
				}
			}
			if s[6] == 49 { // 信道参数
				m := fmt.Sprintf("%08b%08b", svrmsg.WlstCom_3E81.ArgsMark[x+1], svrmsg.WlstCom_3E81.ArgsMark[x])
				x += 2
				if m[15] == 49 { // 信道连接方式
					svrmsg.WlstCom_3E81.Channel.Channel1Type = gopsu.String2Int32(fmt.Sprintf("%08b", d[j])[4:], 2)
					svrmsg.WlstCom_3E81.Channel.Channel2Type = gopsu.String2Int32(fmt.Sprintf("%08b", d[j])[:4], 2)
					j++
				}
				if m[14] == 49 { // 信道1服务器地址
					for i := 0; i < 4; i++ {
						svrmsg.WlstCom_3E81.Channel.Channel1Ip = append(svrmsg.WlstCom_3E81.Channel.Channel1Ip, int32(d[j]))
						j++
					}
				}
				if m[13] == 49 { // 信道1服务器端口
					svrmsg.WlstCom_3E81.Channel.Channel1Port = int32(d[j])*256 + int32(d[j+1])
					j += 2
				}
				if m[12] == 49 { // 信道1本地端口
					svrmsg.WlstCom_3E81.Channel.Channel1LocalPort = int32(d[j])*256 + int32(d[j+1])
					j += 2
				}
				if m[11] == 49 { // 信道2服务器地址
					for i := 0; i < 4; i++ {
						svrmsg.WlstCom_3E81.Channel.Channel2Ip = append(svrmsg.WlstCom_3E81.Channel.Channel2Ip, int32(d[j]))
						j++
					}
				}
				if m[10] == 49 { // 信道2服务器端口
					svrmsg.WlstCom_3E81.Channel.Channel2Port = int32(d[j])*256 + int32(d[j+1])
					j += 2
				}
				if m[9] == 49 { // 信道2本地端口
					svrmsg.WlstCom_3E81.Channel.Channel2LocalPort = int32(d[j])*256 + int32(d[j+1])
					j += 2
				}
				if m[8] == 49 { // 心跳参数
					svrmsg.WlstCom_3E81.Channel.KeepAlive = int32(d[j])
				}
				if m[7] == 49 { // 心跳参数
					svrmsg.WlstCom_3E81.Channel.Idle = int32(d[j])
				}
			}
			if s[5] == 49 { // 接口参数
				m := fmt.Sprintf("%08b", svrmsg.WlstCom_3E81.ArgsMark[x])
				x += 2
				if m[7] == 49 {
					svrmsg.WlstCom_3E81.Interface.Port1Br = gopsu.String2Int32(fmt.Sprintf("%08b", d[j])[4:], 2)
					svrmsg.WlstCom_3E81.Interface.Port2Br = gopsu.String2Int32(fmt.Sprintf("%08b", d[j])[:4], 2)
					j++
					svrmsg.WlstCom_3E81.Interface.Port1Rc = gopsu.String2Int32(fmt.Sprintf("%08b", d[j])[5:], 2)
					svrmsg.WlstCom_3E81.Interface.Port2Rc = gopsu.String2Int32(fmt.Sprintf("%08b", d[j])[2:5], 2)
					svrmsg.WlstCom_3E81.Interface.WorkMode = gopsu.String2Int32(fmt.Sprintf("%08b", d[j])[:2], 2)
					j++
				}
			}
			if s[4] == 49 { // 短信参数
				m := fmt.Sprintf("%08b%08b", svrmsg.WlstCom_3E81.ArgsMark[x+1], svrmsg.WlstCom_3E81.ArgsMark[x])
				x += 2
				if m[15] == 49 { // 主台号码数量
					svrmsg.WlstCom_3E81.Sms.ValidCount = int32(d[j])
					j++
				}
				if m[14] == 49 { // 主台sim卡号码1
					svrmsg.WlstCom_3E81.Sms.Sim = append(svrmsg.WlstCom_3E81.Sms.Sim, string(d[j:j+11]))
					j += 11
				}
				if m[13] == 49 { // 主台sim卡号码2
					svrmsg.WlstCom_3E81.Sms.Sim = append(svrmsg.WlstCom_3E81.Sms.Sim, string(d[j:j+11]))
					j += 11
				}
				if m[12] == 49 { // 主台sim卡号码3
					svrmsg.WlstCom_3E81.Sms.Sim = append(svrmsg.WlstCom_3E81.Sms.Sim, string(d[j:j+11]))
					j += 11
				}
				if m[11] == 49 { // 主台sim卡号码4
					svrmsg.WlstCom_3E81.Sms.Sim = append(svrmsg.WlstCom_3E81.Sms.Sim, string(d[j:j+11]))
					j += 11
				}
				if m[10] == 49 { // 主台sim卡号码5
					svrmsg.WlstCom_3E81.Sms.Sim = append(svrmsg.WlstCom_3E81.Sms.Sim, string(d[j:j+11]))
					j += 11
				}
				if m[9] == 49 { // 主台sim卡号码6
					svrmsg.WlstCom_3E81.Sms.Sim = append(svrmsg.WlstCom_3E81.Sms.Sim, string(d[j:j+11]))
					j += 11
				}
				if m[8] == 49 { // 主台sim卡号码7
					svrmsg.WlstCom_3E81.Sms.Sim = append(svrmsg.WlstCom_3E81.Sms.Sim, string(d[j:j+11]))
					j += 11
				}
				if m[7] == 49 { // 主台sim卡号码8
					svrmsg.WlstCom_3E81.Sms.Sim = append(svrmsg.WlstCom_3E81.Sms.Sim, string(d[j:j+11]))
					j += 11
				}
				if m[6] == 49 { // 主台sim卡号码9
					svrmsg.WlstCom_3E81.Sms.Sim = append(svrmsg.WlstCom_3E81.Sms.Sim, string(d[j:j+11]))
					j += 11
				}
				if m[5] == 49 { // 主台sim卡号码10
					svrmsg.WlstCom_3E81.Sms.Sim = append(svrmsg.WlstCom_3E81.Sms.Sim, string(d[j:j+11]))
					j += 11
				}
				if m[4] == 49 { // 查流量短信指令
					svrmsg.WlstCom_3E81.Sms.Yecx = string(d[j : j+16])
					j += 16
				}
			}
			if s[3] == 49 { // 地址参数
				m := fmt.Sprintf("%08b", svrmsg.WlstCom_3E81.ArgsMark[x])
				x += 2
				if m[7] == 49 { // 模块地址
					svrmsg.WlstCom_3E81.Address.Addr = string(d[j : j+11])
					j += 11
				}
				if m[6] == 49 { // 线路地址
					j += 32
				}
				if m[5] == 49 { // 模块硬件批号
					j += 20
				}
			}
			if s[2] == 49 { // 状态参数
				m := fmt.Sprintf("%08b%08b", svrmsg.WlstCom_3E81.ArgsMark[x+1], svrmsg.WlstCom_3E81.ArgsMark[x])
				x += 2
				ss := ""
				if m[15] == 49 { // iccid
					j += 20
				}
				if m[14] == 49 { // imsi
					j += 15
				}
				if m[13] == 49 { // imei（gsm）
					svrmsg.WlstCom_3E81.Status.Imei = gopsu.String2Int64(string(d[j:j+15]), 10)
					f.Remark, _ = sjson.Set(f.Remark, "imei", svrmsg.WlstCom_3E81.Status.Imei)
					j += 15
				}
				if m[12] == 49 { // 射频软件版本
					j += 20
				}
				if m[11] == 49 { // vcsq
					ss += fmt.Sprintf(",%d", d[j])
					j++
				}
				if m[10] == 49 { // lac
					j += 2
				}
				if m[9] == 49 { // ci
					j += 2
				}
				if m[8] == 49 { // 工作状态
					j++
				}
				if m[7] == 49 { // 模块状态
					ss += fmt.Sprintf(",%02x", d[j])
					j++
				}
				if m[6] == 49 { // 模块软件版本
					svrmsg.WlstCom_3E81.Status.Ver = strings.TrimSpace(string(d[j : j+20]))
					f.Remark, _ = sjson.Set(f.Remark, "ver", svrmsg.WlstCom_3E81.Status.Ver)
					j += 20
				}
				if m[5] == 49 { // 掉线原因
					ss += fmt.Sprintf(",%02x%02x", d[j], d[j+1])
					j += 2
				}
				if m[4] == 49 { // 掉线次数
					ss += fmt.Sprintf(",%d", int(d[j])+int(d[j+1])*256)
					j += 2
				}
				if m[3] == 49 { // 重启次数
					ss += fmt.Sprintf(",%02x", d[j])
					j++
				}
				if m[2] == 49 { // 时间
					j += 4
				}
				if m[1] == 49 { // 当前流量
					j += 4
				}
				if m[0] == 49 { // 总流量
					j += 4
				}
				svrmsg.WlstCom_3E81.Status.State = ss
			}
		}
		ff := &Fwd{
			DataCmd:  svrmsg.Head.Cmd,
			DataType: DataTypeBase64,
			DataDst:  "6",
			DstType:  SockUpgrade,
			Tra:      TraDirect,
			Job:      JobSend,
			// Src:      gopsu.Bytes2String(d, "-"),
			DataMsg: CodePb2(svrmsg),
		}
		lstf = append(lstf, ff)
	case 0x82:
		svrmsg.WlstCom_3E82 = &msgctl.WlstCom_3E82{}
		svrmsg.WlstCom_3E82.Status = int32(d[16])
		svrmsg.WlstCom_3E82.GroupMark = int32(d[17])
		l := int(d[2]) + int(d[3])*256 + 4
		for i := 18; i < l; i += 2 {
			svrmsg.WlstCom_3E82.ArgsMark = append(svrmsg.WlstCom_3E82.ArgsMark, int32(d[i])+int32(d[i+1])*256)
		}
		zm := svrmsg.WlstCom_3E82
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		ff := &Fwd{
			DataCmd:  svrmsg.Head.Cmd,
			DataType: DataTypeBase64,
			DataDst:  "6",
			DstType:  SockUpgrade,
			Tra:      TraDirect,
			Job:      JobSend,
			// Src:      gopsu.Bytes2String(d, "-"),
			DataMsg: CodePb2(svrmsg),
		}
		lstf = append(lstf, ff)
	default:
		f.Ex = fmt.Sprintf("Unhandled com protocol: %s", gopsu.Bytes2String(d, "-"))
		lstf = append(lstf, f)
		return lstf
	}

	if len(f.DataCmd) > 0 {
		if len(f.DataMsg) == 0 {
			f.DataMsg = CodePb2(svrmsg)
		}
		lstf = append(lstf, f)
	}

	return lstf
}

// 处理GPS定位数据
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
//  tra：是否485数据1-非485,2-485
//  tmladdr: 为485数据时，父设备物理地址
// Return:
// 	lstf: 处理反馈结果
func dataGps(d []byte, ip *int64, portlocal *int) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DstType:  SockData,
		Tra:      TraDirect,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}

	if len(f.DataCmd) > 0 {
		// f.DataMsg = CodePb2(svrmsg)
		lstf = append(lstf, f)
	}

	return lstf
}

// 处理漏电数据
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
//  tra：是否485数据1-非485,2-485
//  tmladdr: 为485数据时，父设备物理地址
// Return:
// 	lstf: 处理反馈结果
func dataElu(d []byte, ip *int64, tra byte, tmladdr int64, portlocal *int) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      tra,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}
	if !gopsu.CheckCrc16VB(d) {
		f.Ex = fmt.Sprintf("Elu data validation fails")
		lstf = append(lstf, f)
		return lstf
	}

	var cid int32
	cmd := d[4]
	if tmladdr > 0 {
		tra = 2
		f.Addr = tmladdr
		cid = int32(d[3])
	} else {
		tra = 1
		cid = 1
		f.Addr = int64(d[3])
	}
	svrmsg := initMsgCtl(fmt.Sprintf("wlst.elu.62%02x", cmd), f.Addr, *ip, 1, tra, cid, portlocal)
	f.DataCmd = svrmsg.Head.Cmd
	switch cmd {
	case 0xd5: // 设置地址应答
		svrmsg.WlstTml.WlstElu_62D5 = &msgctl.WlstElu_6255{}
		svrmsg.WlstTml.WlstElu_62D5.NewAddr = int32(f.Addr)
		if d[5] == 0xaa {
			svrmsg.WlstTml.WlstElu_62D5.Status = 1
		} else {
			svrmsg.WlstTml.WlstElu_62D5.Status = 0
		}
		zm := svrmsg.WlstTml.WlstElu_62D5
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xd6: // 设置运行参数应答
		svrmsg.WlstTml.WlstElu_62D6 = &msgctl.WlstElu_6256{}
		if d[5] == 0xaa {
			svrmsg.WlstTml.WlstElu_62D6.Status = 1
		} else {
			svrmsg.WlstTml.WlstElu_62D6.Status = 0
		}
		zm := svrmsg.WlstTml.WlstElu_62D6
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xd7: // 手动操作应答
		svrmsg.WlstTml.WlstElu_62D7 = &msgctl.WlstElu_6257{}
		s := fmt.Sprintf("%08b%08b", d[6], d[5])
		for i := 14; i > -2; i -= 2 {
			svrmsg.WlstTml.WlstElu_62D7.OptDo = append(svrmsg.WlstTml.WlstElu_62D7.OptDo, gopsu.String2Int32(s[i:i+2], 2))
		}
		if d[7] == 0xaa {
			svrmsg.WlstTml.WlstElu_62D7.Status = 1
		} else {
			svrmsg.WlstTml.WlstElu_62D7.Status = 0
		}
		zm := svrmsg.WlstTml.WlstElu_62D7
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xd9, 0xe0: // 选测数据
		svrmsg.WlstTml.WlstElu_62D8 = &msgctl.WlstElu_62D8{}
		for i := 0; i < 4; i++ {
			ad := &msgctl.WlstElu_62D8_AlarmData{}
			ad.SwitchStatus = append(ad.SwitchStatus, gopsu.Byte2Int32s(d[i*9+5], true)...)
			ad.AlarmValueSet = int32(d[i*9+7])*256 + int32(d[i*9+6])
			ad.OptDelay = (int32(d[i*9+9])*256 + int32(d[i*9+8])) * 10
			ad.ElValue = int32(d[i*9+11])*256 + int32(d[i*9+10])
			ad.NowValue = int32(d[i*9+13])*256 + int32(d[i*9+12])
			svrmsg.WlstTml.WlstElu_62D8.AlarmData = append(svrmsg.WlstTml.WlstElu_62D8.AlarmData, ad)
		}
		zm := svrmsg.WlstTml.WlstElu_62D8
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xda: // 事件查询
	case 0xdb: // 设置检测门限
		svrmsg.WlstTml.WlstElu_62Db = &msgctl.WlstElu_625B{}
		if d[5] == 0xaa {
			svrmsg.WlstTml.WlstElu_62Db.Status = 1
		} else {
			svrmsg.WlstTml.WlstElu_62Db.Status = 0
		}
		zm := svrmsg.WlstTml.WlstElu_62Db
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xdc: // 设置时钟
		svrmsg.WlstTml.WlstElu_62Dc = &msgctl.WlstElu_625C{}
		if d[5] == 0xaa {
			svrmsg.WlstTml.WlstElu_62Dc.Status = 1
		} else {
			svrmsg.WlstTml.WlstElu_62Dc.Status = 0
		}
		zm := svrmsg.WlstTml.WlstElu_62Dc
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xdd: // 招测参数
		svrmsg.WlstTml.WlstElu_62Dd = &msgctl.WlstElu_6256{}
		ll := d[2]
		loopmark := gopsu.ReverseString(fmt.Sprintf("%08b", d[5]))
		if (ll-3)/5 < 5 {
			loopmark = loopmark[:4]
		}
		for k, v := range loopmark {
			wa := &msgctl.WlstElu_6256_WorkArgv{}
			if v == 48 {
				wa.LoopMark = 0
			} else {
				wa.LoopMark = 1
			}
			wa.WorkMode = int32(d[k*5+6])
			wa.AlarmValueSet = int32(d[k*5+7]) + int32(d[k*5+8])*256
			wa.OptDelay = (int32(d[k*5+9]) + int32(d[k*5+10])*256) * 10
			svrmsg.WlstTml.WlstElu_62Dd.WorkArgv = append(svrmsg.WlstTml.WlstElu_62Dd.WorkArgv, wa)
		}
		svrmsg.WlstTml.WlstElu_62Dd.Status = 1

		zm := svrmsg.WlstTml.WlstElu_62Dd
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xde: // 招测时钟
		svrmsg.WlstTml.WlstElu_62De = &msgctl.WlstElu_625C{}
		svrmsg.WlstTml.WlstElu_62De.Status = 1
		svrmsg.WlstTml.WlstElu_62De.DtTimer = gopsu.Time2Stamp(fmt.Sprintf("%02d-%02d-%02d %02d:%02d:00", int32(d[5])+2000, d[6], d[7], d[8], d[9]))

		zm := svrmsg.WlstTml.WlstElu_62De
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	case 0xdf: // 复位
		svrmsg.WlstTml.WlstElu_62Df = &msgctl.WlstElu_6255{}
		if d[5] == 0xaa {
			svrmsg.WlstTml.WlstElu_62Df.Status = 1
		} else {
			svrmsg.WlstTml.WlstElu_62Df.Status = 0
		}
		zm := svrmsg.WlstTml.WlstElu_62Df
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
	default:
		f.Ex = "Unhandled elu data"
		lstf = append(lstf, f)
		return lstf
	}

	if len(f.DataCmd) > 0 {
		f.DataMsg = CodePb2(svrmsg)
		lstf = append(lstf, f)
	}
	return lstf
}

// 处理主报数据
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
//  tra：是否485数据1-非485,2-485
//  tmladdr: 为485数据时，父设备物理地址
// Return:
// 	lstf: 处理反馈结果
func dataD0(d []byte, ip *int64, tra byte, tmladdr int64, portlocal *int) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      tra,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}
	// defer func() {
	// 	if ex := recover(); ex != nil {
	// 		f.Src = gopsu.Bytes2String(d, "-")
	// 		f.Ex = fmt.Sprintf("%+v", errors.WithStack(ex.(error)))
	// 		lstf = append(lstf, f)
	// 	}
	// }()

	svrmsg := initMsgCtl("", tmladdr, *ip, 1, tra, 1, portlocal)
	if d[3] == 0x62 { // 漏电保护
		if tmladdr > 0 {
			f.Addr = tmladdr
			svrmsg.Args.Addr = append(svrmsg.Args.Addr, tmladdr)
			svrmsg.Args.Cid = int32(d[4])
		} else {
			f.Addr = int64(d[4])
			svrmsg.Args.Addr = append(svrmsg.Args.Addr, f.Addr)
			svrmsg.Args.Cid = 1
		}
		// f.DataCmd = fmt.Sprintf("wlst.elu.62%02x", d[5])
		svrmsg.Head.Cmd = fmt.Sprintf("wlst.elu.62%02x", d[5])
		l := d[2]
		if !gopsu.CheckCrc16VB(d[:l+3]) {
			f.Ex = fmt.Sprintf("Elu data crc validation failed")
			lstf = append(lstf, f)
			return lstf
		}
		if d[5] == 0xd8 || d[5] == 0xe1 {
			svrmsg.WlstTml.WlstElu_62D8 = &msgctl.WlstElu_62D8{}
			for i := 0; i < 4; i++ {
				ad := &msgctl.WlstElu_62D8_AlarmData{}
				a := fmt.Sprintf("%08b", d[i*9+5+1])
				for j := 7; j >= 0; j-- {
					ad.SwitchStatus = append(ad.SwitchStatus, gopsu.String2Int32(a[j:j+1], 2))
				}
				ad.AlarmValueSet = int32(d[i*9+7+1])*256 + int32(d[i*9+6+1])
				ad.OptDelay = (int32(d[i*9+9+1])*256 + int32(d[i*9+8+1])) * 10
				ad.ElValue = int32(d[i*9+11+1])*256 + int32(d[i*9+10+1])
				ad.NowValue = int32(d[i*9+13+1])*256 + int32(d[i*9+12+1])
				svrmsg.WlstTml.WlstElu_62D8.AlarmData = append(svrmsg.WlstTml.WlstElu_62D8.AlarmData, ad)
			}
			ff := &Fwd{
				DataType: DataTypeBase64,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				Src:      gopsu.Bytes2String(d, "-"),
				DataMsg:  CodePb2(svrmsg),
				DataCmd:  svrmsg.Head.Cmd,
			}
			zm := svrmsg.WlstTml.WlstElu_62D8
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				ff.DataMQ = b
			}
			lstf = append(lstf, ff)
			var br, rc byte
			if tra == 2 {
				br = 5
				rc = 0
			}
			ff2 := &Fwd{
				Addr:     f.Addr,
				DataType: DataTypeBytes,
				DataPT:   3000,
				DataDst:  fmt.Sprintf("wlst-elu-%d", f.Addr),
				DstType:  1,
				Tra:      tra,
				Job:      JobSend,
				Src:      gopsu.Bytes2String(d, "-"),
				DataMsg:  DoCommand(1, 1, byte(tra), tmladdr, svrmsg.Args.Cid, "wlst.elu.6258", []byte{0xaa}, br, rc),
				// DataMsg:  gopsu.Bytes2String(DoCommand(1, 1, byte(tra), tmladdr, svrmsg.Args.Cid, "wlst.elu.6258", []byte{0xaa}, br, rc), "-"),
				DataCmd: svrmsg.Head.Cmd,
			}
			if tra == 2 {
				ff2.DataDst = fmt.Sprintf("wlst-rtu-%d", f.Addr)
			}
			lstf = append(lstf, ff2)
			return lstf
		}
	}
	if bytes.Contains(jyesureply, []byte{d[3]}) && len(d) == 17 { // 江阴节能
		svrmsg.WxjyEsuD500 = &msgctl.WxjyEsu_5500{}
		svrmsg.WxjyEsuD700 = &msgctl.WxjyEsuD700{}
		svrmsg.WxjyEsuD800 = &msgctl.WxjyEsuD800{}
		svrmsg.Head.Cmd = fmt.Sprintf("wxjy.esu.%02x00", d[3])
		switch d[3] {
		case 0xd5:
			svrmsg.WxjyEsuD500.TimeNow = fmt.Sprintf("%02d%02d%02d", d[4], d[5], d[6])
			svrmsg.WxjyEsuD500.XTime = append(svrmsg.WxjyEsuD500.XTime, gopsu.String2Int32(fmt.Sprintf("%02d%02d", d[7], d[8]), 10),
				gopsu.String2Int32(fmt.Sprintf("%02d%02d", d[10], d[11]), 10),
				gopsu.String2Int32(fmt.Sprintf("%02d%02d", d[13], d[14]), 10))
			svrmsg.WxjyEsuD500.XVoltage = append(svrmsg.WxjyEsuD500.XVoltage, int32(d[9]), int32(d[12]), int32(d[15]))
			ff := &Fwd{
				DataType: DataTypeBase64,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				Src:      gopsu.Bytes2String(d, "-"),
				DataMsg:  CodePb2(svrmsg),
				DataCmd:  svrmsg.Head.Cmd,
			}
			zm := svrmsg.WxjyEsuD500
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				ff.DataMQ = b
			}
			lstf = append(lstf, ff)
		case 0xd7:
			svrmsg.WxjyEsuD700.PhaseAIn = int32(d[4])
			svrmsg.WxjyEsuD700.PhaseBIn = int32(d[5])
			svrmsg.WxjyEsuD700.PhaseCIn = int32(d[6])
			svrmsg.WxjyEsuD700.PhaseAOut = int32(d[10])
			svrmsg.WxjyEsuD700.PhaseBOut = int32(d[11])
			svrmsg.WxjyEsuD700.PhaseCOut = int32(d[12])
			ff := &Fwd{
				DataType: DataTypeBase64,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				Src:      gopsu.Bytes2String(d, "-"),
				DataMsg:  CodePb2(svrmsg),
				DataCmd:  svrmsg.Head.Cmd,
			}
			zm := svrmsg.WxjyEsuD700
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				ff.DataMQ = b
			}
			lstf = append(lstf, ff)
		case 0xd8:
			svrmsg.WxjyEsuD800.Status = strconv.FormatInt(int64(d[4]), 10)
			ff := &Fwd{
				DataType: DataTypeBase64,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				Src:      gopsu.Bytes2String(d, "-"),
				DataMsg:  CodePb2(svrmsg),
				DataCmd:  svrmsg.Head.Cmd,
			}
			zm := svrmsg.WxjyEsuD800
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				ff.DataMQ = b
			}
			lstf = append(lstf, ff)
			ff2 := &Fwd{
				DataType: DataTypeBytes,
				DataDst:  fmt.Sprintf("wxjy-esu-%d", f.Addr),
				DstType:  1,
				Tra:      tra,
				Job:      JobSend,
				Src:      gopsu.Bytes2String(d, "-"),
				DataMsg:  SendJY58,
				DataCmd:  "wxjy.esu.5800",
			}
			lstf = append(lstf, ff2)
			return lstf
		}
	}
	if d[3] == 0x1b && d[4] == 0x94 { // 节能主动告警
		ff := &Fwd{
			Addr:     f.Addr,
			DataType: DataTypeBytes,
			DataPT:   3000,
			DataDst:  fmt.Sprintf("wlst-esu-%d", f.Addr),
			DstType:  1,
			Tra:      tra,
			Job:      JobSend,
			Src:      gopsu.Bytes2String(d, "-"),
			DataMsg:  SendEsu1c00,
			DataCmd:  svrmsg.Head.Cmd,
		}
		lstf = append(lstf, ff)
		ff2 := &Fwd{
			Addr:     f.Addr,
			DataType: DataTypeBytes,
			DataPT:   3000,
			DataDst:  fmt.Sprintf("wxjy-esu-%d", f.Addr),
			DstType:  1,
			Tra:      tra,
			Job:      JobSend,
			Src:      gopsu.Bytes2String(d, "-"),
			DataMsg:  SendEsu1300,
			DataCmd:  svrmsg.Head.Cmd,
		}
		lstf = append(lstf, ff2)
		return lstf
	}
	if d[3] == 0xa8 { // 光照度
		svrmsg.Head.Cmd = "wlst.als.a700"
		l := d[2]
		if !gopsu.CheckCrc16VB(d[:l+3]) {
			f.Ex = fmt.Sprintf("Ldu data crc validation failed")
			lstf = append(lstf, f)
			return lstf
		}
		svrmsg.WlstTml.WlstAlsA700 = &msgctl.WlstAlsA700{}
		s := fmt.Sprintf("%08b", d[14])
		var luxsum, luxcount, x float64
		if s[1:2] == "1" {
			x = 65536.0
		} else {
			x = 32768.0
		}
		if s[7:8] == "1" {
			luxcount++
			luxsum += (float64(int(d[6])+int(d[7])*256) / x) * 10000.0
		}
		if s[6:7] == "1" {
			luxcount++
			luxsum += (float64(int(d[8])+int(d[9])*256) / x) * 10000.0
		}
		if s[5:6] == "1" {
			luxcount++
			luxsum += (float64(int(d[10])+int(d[11])*256) / x) * 10000.0
		}
		if s[4:5] == "1" {
			luxcount++
			luxsum += (float64(int(d[12])+int(d[13])*256) / x) * 10000.0
		}
		if luxcount > 0 {
			svrmsg.WlstTml.WlstAlsA700.Lux = luxsum / luxcount
		} else {
			svrmsg.WlstTml.WlstAlsA700.Lux = 0
			svrmsg.WlstTml.WlstAlsA700.Error = 1
		}
		svrmsg.WlstTml.WlstAlsA700.Addr = int32(d[5])
		if luxcount > 2 {
			svrmsg.WlstTml.WlstAlsA700.Error = 0
		} else {
			svrmsg.WlstTml.WlstAlsA700.Error = 1
		}
		ff := &Fwd{
			DataType: DataTypeBase64,
			DataDst:  "2",
			DstType:  SockData,
			Tra:      tra,
			Job:      JobSend,
			Src:      gopsu.Bytes2String(d, "-"),
			DataMsg:  CodePb2(svrmsg),
			DataCmd:  svrmsg.Head.Cmd,
		}
		zm := svrmsg.WlstTml.WlstAlsA700
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			ff.DataMQ = b
		}
		lstf = append(lstf, ff)
		return lstf
	}
	if d[5] == 0x95 { // 线路检测485主报
		l := d[2]
		if !gopsu.CheckCrc16VB(d[:l+3]) {
			f.Ex = fmt.Sprintf("Ldu data crc validation failed")
			lstf = append(lstf, f)
			return lstf
		}
		svrmsg.Head.Cmd = "wlst.ldu.a600"
		svrmsg.WlstTml.WlstLduA600 = &msgctl.WlstLduA600{}
		ll := l - 6
		loop := fmt.Sprintf("%08b", d[6])
		svrmsg.WlstTml.WlstLduA600.LoopMark = int32(d[6])
		var x int
		if ll%16 == 0 {
			for j := 0; j < 8; j++ {
				if loop[7-j:8-j] == "1" {
					xloopdata := &msgctl.WlstLduA600_LduLoopData{}
					xloopdata.XVoltage = float64(int32(d[16*x+7])+int32(d[16*x+8])*256) / 100.0
					xloopdata.XCurrent = float64(int32(d[16*x+9])+int32(d[16*x+10])*256) / 100.0
					xloopdata.XActivePower = float64(int32(d[16*x+11])+int32(d[16*x+12])*256) / 100.0
					xloopdata.XReactivePower = float64(int32(d[16*x+13])+int32(d[16*x+14])*256) / 100.0
					xloopdata.XPowerFactor = float64(d[16*x+15]) / 100.0
					xloopdata.XLightingRate = float64(d[16*x+16])
					xloopdata.XSignalStrength = int32(d[16*x+17]) * 10
					xloopdata.XImpedance = int32(d[16*x+18]) * 10
					xloopdata.XUsefulSignal = int32(d[16*x+19])
					xloopdata.XAllSignal = int32(d[16*x+20])
					xloopdata.XDetectionFlag = int32(d[16*x+21])
					xloopdata.XAlarmFlag = int32(d[16*x+22])
					x++
					svrmsg.WlstTml.WlstLduA600.LduLoopData = append(svrmsg.WlstTml.WlstLduA600.LduLoopData, xloopdata)
				}
			}
			ff := &Fwd{
				DataType: DataTypeBase64,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				Src:      gopsu.Bytes2String(d, "-"),
				DataMsg:  CodePb2(svrmsg),
				DataCmd:  svrmsg.Head.Cmd,
			}
			zm := svrmsg.WlstTml.WlstLduA600
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				ff.DataMQ = b
			}
			lstf = append(lstf, ff)
		}
		if ll%19 == 0 {
			for j := 0; j < 8; j++ {
				if loop[7-j:8-j] == "1" {
					xloopdata := &msgctl.WlstLduA600_LduLoopData{}
					xloopdata.XVoltage = float64(int32(d[16*x+7])+int32(d[16*x+8])*256) / 100.0
					xloopdata.XCurrent = float64(int32(d[16*x+9])+int32(d[16*x+10])*256) / 100.0
					xloopdata.XActivePower = float64(int32(d[16*x+11])+int32(d[16*x+12])*256) / 100.0
					xloopdata.XReactivePower = float64(int32(d[16*x+13])+int32(d[16*x+14])*256) / 100.0
					xloopdata.XPowerFactor = float64(d[16*x+15]) / 100.0
					xloopdata.XLightingRate = float64(d[16*x+16])
					xloopdata.XSignalStrength = int32(d[16*x+17]) * 10
					xloopdata.XImpedance = int32(d[16*x+18]) + int32(d[16*x+19])*256
					xloopdata.XUsefulSignal = int32(d[16*x+20])
					xloopdata.XAllSignal = int32(d[16*x+21])
					xloopdata.XDetectionFlag = int32(d[16*x+22])
					xloopdata.XAlarmFlag = int32(d[16*x+23])
					x++
					svrmsg.WlstTml.WlstLduA600.LduLoopData = append(svrmsg.WlstTml.WlstLduA600.LduLoopData, xloopdata)
				}
			}
			ff := &Fwd{
				DataType: DataTypeBase64,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				Src:      gopsu.Bytes2String(d, "-"),
				DataMsg:  CodePb2(svrmsg),
				DataCmd:  svrmsg.Head.Cmd,
			}
			zm := svrmsg.WlstTml.WlstLduA600
			b, ex := pb2.Marshal(zm)
			if ex == nil {
				ff.DataMQ = b
			}
			lstf = append(lstf, ff)
		}
		return lstf
	}
	if d[3] == 0x90 && d[4] == 0x7e && d[5] == 0x90 { // 单灯主报参数
		return dataSlu(d[4:d[2]+3], ip, tra, tmladdr, portlocal)
	}
	return lstf
}

// 处理安徽合肥协议数据
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
// Return:
// 	lstf: 处理反馈结果
func dataAhhf(d []byte, ip *int64, portlocal *int) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      TraDirect,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}
	// defer func() {
	// 	if ex := recover(); ex != nil {
	// 		f.Src = gopsu.Bytes2String(d, "-")
	// 		f.Ex = fmt.Sprintf("%+v", errors.WithStack(ex.(error)))
	// 		lstf = append(lstf, f)
	// 	}
	// }()

	afn := fmt.Sprintf("%08b", d[12])
	seq := fmt.Sprintf("%08b", d[13])
	idx, _ := strconv.ParseInt(seq[4:], 2, 0)
	cmd, _ := strconv.ParseInt(afn[4:], 2, 0)
	ll := int(d[1]) + int(d[2])*256
	addr := ""
	for i := 10; i > 3; i-- {
		addr += fmt.Sprintf("%02d", gopsu.Bcd2Int8(d[i]))
	}
	f.Addr = gopsu.String2Int64(addr, 10)
	if afn[0] == 0 {
		f.Ex = "Ahhf illegal data sources."
		lstf = append(lstf, f)
		return lstf
	}
	if !gopsu.CheckCrc16VB(d[4 : len(d)-1]) {
		f.Ex = "Ahhf data validation fails"
		lstf = append(lstf, f)
		return lstf
	}
	svrmsg := initMsgCtl("", f.Addr, *ip, 2, 1, 1, portlocal)
	switch cmd {
	case 0x04: // 设置参数应答
		nomore := false
		f.DataCmd = "ahhf.rtu.6804"
		svrmsg.AhhfRtu_6804 = &msgctl.AhhfRtu_6804{}
		j := 14
		for {
			if nomore {
				break
			}
			// da1 := d[j]
			// da2 := d[j+1]
			j += 2
			dt1 := fmt.Sprintf("%08b", d[j])
			dt2 := d[j+1]
			// dtl := d[j+2] + d[j+3]*256
			j += 4
			switch dt2 {
			case 0:
				s := fmt.Sprintf("%08b", d[j])
				j++
				if dt1[7] == 1 {
					svrmsg.AhhfRtu_6804 = &msgctl.AhhfRtu_6804{
						CmdIdx:   int32(idx),
						DataMark: append(svrmsg.AhhfRtu_6804.DataMark, 1),
					}
					svrmsg.AhhfRtu_6804.Status = append(svrmsg.AhhfRtu_6804.Status, int32(s[7]))
				}
				if dt1[6] == 1 {
					svrmsg.AhhfRtu_6804 = &msgctl.AhhfRtu_6804{
						CmdIdx:   int32(idx),
						DataMark: append(svrmsg.AhhfRtu_6804.DataMark, 1),
					}
					svrmsg.AhhfRtu_6804.Status = append(svrmsg.AhhfRtu_6804.Status, int32(s[6]))
				}
				if dt1[5] == 1 {
					svrmsg.AhhfRtu_6804 = &msgctl.AhhfRtu_6804{
						CmdIdx:   int32(idx),
						DataMark: append(svrmsg.AhhfRtu_6804.DataMark, 1),
					}
					svrmsg.AhhfRtu_6804.Status = append(svrmsg.AhhfRtu_6804.Status, int32(s[5]))
				}
				if dt1[4] == 1 {
					f.DataCmd = "ahhf.rtu.9200"
					svrmsg.WlstTml.WlstRtu_9200 = &msgctl.WlstRtuAns{
						CmdIdx: int32(idx),
						Status: append(svrmsg.WlstTml.WlstRtu_9200.Status, int32(s[5])),
					}
				}
			case 1:
				s := fmt.Sprintf("%08b", d[j])
				j++
				if dt1[7] == 1 {
					f.DataCmd = "ahhf.rtu.70e0"
					svrmsg.WlstTml.WlstRtu_70E0 = &msgctl.WlstRtu_70E0{
						CmdIdx: int32(idx),
						Status: int32(s[7]),
					}
				}
			}
			if j-4 >= ll {
				nomore = true
			}
		}
	case 0x05: // 开关灯应答
		nomore := false
		f.DataCmd = "ahhf.rtu.6805"
		j := 14
		for {
			if nomore {
				break
			}
			// da1 := d[j]
			// da2 := d[j+1]
			j += 2
			dt1 := fmt.Sprintf("%08b", d[j])
			dt2 := d[j+1]
			// dtl := d[j+2] + d[j+3]*256
			j += 4
			switch dt2 {
			case 0:
				if dt1[7] == 1 {
					f.DataCmd = "ahhf.rtu.cb00"
					svrmsg.WlstTml.WlstRtuCb00 = &msgctl.WlstRtuAns{
						CmdIdx: int32(idx),
					}
					loopCount := d[j]
					j++
					for i := byte(0); i < loopCount; i++ {
						svrmsg.WlstTml.WlstRtuCb00.DataPoint = append(svrmsg.WlstTml.WlstRtuCb00.DataPoint, int32(d[j]))
						svrmsg.WlstTml.WlstRtuCb00.Status = append(svrmsg.WlstTml.WlstRtuCb00.Status, int32(d[j+1]))
						j += 2
					}
				}
			}
			if j-4 >= ll {
				nomore = true
			}
		}
	case 0x09:
		nomore := false
		f.DataCmd = "ahhf.rtu.6809"
		j := 14
		for {
			if nomore {
				break
			}
			// da1 := d[j]
			// da2 := d[j+1]
			j += 2
			dt1 := fmt.Sprintf("%08b", d[j])
			dt2 := d[j+1]
			// dtl := d[j+2] + d[j+3]*256
			j += 4
			switch dt2 {
			case 0:
				if dt1[7] == 1 {
					f.DataCmd = "ahhf.rtu.dc00"
					svrmsg.WlstTml.WlstRtuDc00 = &msgctl.WlstRtuDc00{}
					s := ""
					for i := 0; i < 22; i++ {
						s += string(d[j+i])
						if i == 7 || i == 8 || i == 9 || i == 15 || i == 19 {
							s += ","
						}
					}
					j += 22
					svrmsg.WlstTml.WlstRtuDc00.Ver = s
				}
			}
			if j-4 >= ll {
				nomore = true
			}
		}
	case 0x0a: // 读取参数应答
		nomore := false
		f.DataCmd = "ahhf.rtu.680a"
		svrmsg.AhhfRtu_680A = &msgctl.AhhfRtu_6804{}
		j := 14
		for {
			if nomore {
				break
			}
			// da1 := d[j]
			// da2 := d[j+1]
			j += 2
			dt1 := fmt.Sprintf("%08b", d[j])
			dt2 := d[j+1]
			// dtl := d[j+2] + d[j+3]*256
			j += 4
			switch dt2 {
			case 0:
				if dt1[7] == 1 { // 开关量输出设置应答
					svrmsg.AhhfRtu_680A.DataMark = append(svrmsg.AhhfRtu_680A.DataMark, 1)
					svrmsg.AhhfRtu_680A.SwitchOut.SwitchOutTotal = int32(d[j])
					j++
					for i := int32(0); i < svrmsg.AhhfRtu_680A.SwitchOut.SwitchOutTotal; i++ {
						svrmsg.AhhfRtu_680A.SwitchOut.SwitchOutLoop = append(svrmsg.AhhfRtu_680A.SwitchOut.SwitchOutLoop, int32(d[j]))
						j++
					}
				}
				if dt1[6] == 1 { // 开关量输入参数设置应答
					svrmsg.AhhfRtu_680A.DataMark = append(svrmsg.AhhfRtu_680A.DataMark, 2)
					svrmsg.AhhfRtu_680A.SwitchIn.VoltageTransformer = int32(d[j])
					j++
					svrmsg.AhhfRtu_680A.SwitchIn.LoopTotal = int32(d[j])
					j++
					for i := int32(0); i < svrmsg.AhhfRtu_680A.SwitchIn.LoopTotal; i++ {
						svrmsg.AhhfRtu_680A.SwitchIn.CurrentTransformer = append(svrmsg.AhhfRtu_680A.SwitchIn.CurrentTransformer, int32(d[j])*5)
						svrmsg.AhhfRtu_680A.SwitchIn.CurrentPhase = append(svrmsg.AhhfRtu_680A.SwitchIn.CurrentPhase, int32(d[j+1]))
						j += 2
					}
				}
				if dt1[5] == 1 { // 上下限参数设置应答
					svrmsg.AhhfRtu_680A.DataMark = append(svrmsg.AhhfRtu_680A.DataMark, 3)
					svrmsg.AhhfRtu_680A.SwitchInLimit.VoltageLowlimit = append(svrmsg.AhhfRtu_680A.SwitchInLimit.VoltageLowlimit, float64((int32(d[j+1])*256+int32(d[j]))/100.0))
					j += 2
					svrmsg.AhhfRtu_680A.SwitchInLimit.VoltageUplimit = append(svrmsg.AhhfRtu_680A.SwitchInLimit.VoltageUplimit, float64((int32(d[j+1])*256+int32(d[j]))/100.0))
					j += 2
				}
				if dt1[4] == 1 { // 招测时钟
					f.DataCmd = "ahhf.rtu.9300"
					svrmsg.WlstTml.WlstRtu_9300.TmlDate = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d %d", int32(d[j])+2000, int32(d[j+1]), int32(d[j+2]), int32(d[j+3]), int32(d[j+4]), int32(d[j+5]), int32(d[j+6]))
					j += 7
				}
			case 1:
				if dt1[7] == 1 { // 读取年设置
					f.DataCmd = "ahhf.rtu.70e1"
					svrmsg.WlstTml.WlstRtu_70E1.CmdIdx = int32(idx)
					svrmsg.WlstTml.WlstRtu_70E1.DtStart = gopsu.Time2Stamp(fmt.Sprintf("2017-%02d-%02d 00:00:00", d[j+1], d[j]))
					j += 2
					svrmsg.WlstTml.WlstRtu_70E1.Days = int32(d[j])
					j++
					loopMark := fmt.Sprintf("%08b%08b", d[j+1], d[j])
					j += 2
					for i := 0; i < 16; i++ {
						if loopMark[15-i] == 1 {
							x := int32(d[j]) * svrmsg.WlstTml.WlstRtu_70E1.Days
							yc := &msgctl.WlstRtu_7060_YearCtrl{
								LoopNo:    int32(i + 1),
								TimeCount: int32(d[j]),
							}
							j++
							for k := int32(0); k < x; k++ {
								yc.OptTime = append(yc.OptTime, int32(d[j])*60+int32(d[j+1]))
								yc.OptTime = append(yc.OptTime, int32(d[j+2])*60+int32(d[j+3]))
								j += 4
							}
							svrmsg.WlstTml.WlstRtu_70E1.YearCtrl = append(svrmsg.WlstTml.WlstRtu_70E1.YearCtrl, yc)
						}
					}
				}
			}
			if j-4 >= ll {
				nomore = true
			}
		}
	case 0x0c: // 选测
		nomore := false
		f.DataCmd = "ahhf.rtu.680c"
		svrmsg.WlstTml.WlstRtu_70D0 = &msgctl.WlstRtu_70D0{}
		j := 14
		for {
			if nomore {
				break
			}
			// da1 := d[j]
			// da2 := d[j+1]
			j += 2
			dt1 := fmt.Sprintf("%08b", d[j])
			dt2 := d[j+1]
			// dtl := d[j+2] + d[j+3]*256
			j += 4
			switch dt2 {
			case 0:
				if dt1[7] == 1 { // 终端运行状态
					svrmsg.WlstTml.WlstRtu_70D0.CmdIdx = int32(idx)
					ss := fmt.Sprintf("%08b%08b%08b%08b%08b%08b%08b", d[j+6], d[j+5], d[j+4], d[j+3], d[j+2], d[j+1], d[j])
					j += 7
					ssr := gopsu.ReverseString(ss)
					for _, v := range ssr {
						svrmsg.WlstTml.WlstRtu_70D0.SwitchInStPacked = append(svrmsg.WlstTml.WlstRtu_70D0.SwitchInStPacked, v)
					}
					svrmsg.WlstTml.WlstRtu_70D0.SwitchInSt = gopsu.String2Int64(ss, 2)
					ss = fmt.Sprintf("%08b", d[j])
					j++
					ssr = gopsu.ReverseString(ss)
					for _, v := range ssr {
						svrmsg.WlstTml.WlstRtu_70D0.SwitchOutStPacked = append(svrmsg.WlstTml.WlstRtu_70D0.SwitchOutStPacked, v)
					}
					svrmsg.WlstTml.WlstRtu_70D0.SwitchOutSt = gopsu.String2Int32(ss, 2)
					ss = fmt.Sprintf("%08b", d[j])
					j++
					ssr = gopsu.ReverseString(ss)
					for _, v := range ssr {
						svrmsg.WlstTml.WlstRtu_70D0.TmlStPacked = append(svrmsg.WlstTml.WlstRtu_70D0.TmlStPacked, v)
					}
					svrmsg.WlstTml.WlstRtu_70D0.TmlSt = gopsu.String2Int32(ss, 2)
					for i := 0; i < 4; i++ {
						svrmsg.WlstTml.WlstRtu_70D0.TmlReset = append(svrmsg.WlstTml.WlstRtu_70D0.TmlReset, int32(d[j+i]))
					}
					j += 4
				}
				if dt1[6] == 1 { // 模拟量数据
					sv := &msgctl.WlstRtu_70D0_SamplingVoltage{
						VolA: (float64(d[j+1])*256 + float64(d[j])) / 100.0,
						VolB: (float64(d[j+3])*256 + float64(d[j+2])) / 100.0,
						VolC: (float64(d[j+5])*256 + float64(d[j+4])) / 100.0,
					}
					j += 6
					svrmsg.WlstTml.WlstRtu_70D0.SamplingVoltage = append(svrmsg.WlstTml.WlstRtu_70D0.SamplingVoltage, sv)
					loopCount := int(d[j])
					j++
					for i := 0; i < loopCount; i++ {
						ad := &msgctl.WlstRtu_70D0_AnalogData{
							Voltage: (float64(d[j+1])*256 + float64(d[j])) / 100.0,
							Current: (float64(d[j+3])*256 + float64(d[j+2])) / 100.0,
							Power:   (float64(d[j+5])*256 + float64(d[j+4])) / 100.0,
						}
						j += 6
						svrmsg.WlstTml.WlstRtu_70D0.AnalogData = append(svrmsg.WlstTml.WlstRtu_70D0.AnalogData, ad)
					}
				}
			}
			if j-4 >= ll {
				nomore = true
			}
		}
	case 0x02: // 心跳
		f.DataCmd = ""
	default:
		f.Ex = "Unhandled ahhf data"
		lstf = append(lstf, f)
		return lstf
	}

	if len(f.DataCmd) > 0 {
		svrmsg.Head.Cmd = f.DataCmd
		f.DataMsg = CodePb2(svrmsg)
		lstf = append(lstf, f)
	}

	return lstf
}

// 处理勃洛克单灯数据（未完成）
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
//  tra：是否485数据1-非485,2-485
//  tmladdr: 为485数据时，父设备物理地址
// Return:
// 	lstf: 处理反馈结果
func dataBlk(d []byte, ip *int64, tra byte, tmladdr int64, portlocal *int) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      tra,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}

	if len(f.DataCmd) > 0 {
		// f.DataMsg = CodePb2(svrmsg)
		lstf = append(lstf, f)
	}

	return lstf
}

// 处理节能数据
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
//  tra：是否485数据1-非485,2-485
//  tmladdr: 为485数据时，父设备物理地址
// Return:
// 	lstf: 处理反馈结果
func dataEsu(d []byte, ip *int64, tra byte, tmladdr int64, portlocal *int) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      tra,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}

	// if !gopsu.CheckCrc16VB(d) {
	//     f.Ex = fmt.Sprintf("Esu data validation fails:%s", gopsu.Bytes2String(d, "-"))
	//     lstf = append(lstf, f)
	//     return lstf
	// }
	var cmd, cid int32
	cmd = int32(d[3])
	if tmladdr == 0 {
		f.Addr = 1
		cid = 1
	} else {
		f.Addr = tmladdr
		cid = 1
	}
	svrmsg := initMsgCtl(fmt.Sprintf("wlst.esu.%02x00", cmd), f.Addr, *ip, 1, tra, cid, portlocal)
	f.DataCmd = svrmsg.Head.Cmd
	switch cmd {
	case 0x92: // 招测节能工作参数
		svrmsg.WlstTml.WlstEsu_9200 = &msgctl.WlstEsu_9200{}
		svrmsg.WlstTml.WlstEsu_9200.WarmupTime = int32(d[4])
		svrmsg.WlstTml.WlstEsu_9200.FanStartTemperature = int32(d[5])
		svrmsg.WlstTml.WlstEsu_9200.StopSaver = int32(d[6])
		svrmsg.WlstTml.WlstEsu_9200.ProtectionTemperature = int32(d[7])
		svrmsg.WlstTml.WlstEsu_9200.InputOvervoltage = int32(d[8]) + int32(d[9])*256
		svrmsg.WlstTml.WlstEsu_9200.InputUndervoltage = int32(d[10]) + int32(d[11])*256
		svrmsg.WlstTml.WlstEsu_9200.OutputOverload = int32(d[12]) + int32(d[13])*256
		svrmsg.WlstTml.WlstEsu_9200.OnTime = int32(d[14])*60 + int32(d[15])
		svrmsg.WlstTml.WlstEsu_9200.OffTime = int32(d[16])*60 + int32(d[17])
		svrmsg.WlstTml.WlstEsu_9200.PhaseCount = int32(d[18])
		zm := svrmsg.WlstTml.WlstEsu_9200
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.wt", svrmsg.WlstTml.WlstEsu_9200.WarmupTime)
			jv, _ = sjson.Set(jv, "data.stmp", svrmsg.WlstTml.WlstEsu_9200.FanStartTemperature)
			jv, _ = sjson.Set(jv, "data.etmp", svrmsg.WlstTml.WlstEsu_9200.StopSaver)
			jv, _ = sjson.Set(jv, "data.ptmp", svrmsg.WlstTml.WlstEsu_9200.ProtectionTemperature)
			jv, _ = sjson.Set(jv, "data.iovl", svrmsg.WlstTml.WlstEsu_9200.InputOvervoltage)
			jv, _ = sjson.Set(jv, "data.iuvl", svrmsg.WlstTml.WlstEsu_9200.InputUndervoltage)
			jv, _ = sjson.Set(jv, "data.oovl", svrmsg.WlstTml.WlstEsu_9200.OutputOverload)
			jv, _ = sjson.Set(jv, "data.ot", svrmsg.WlstTml.WlstEsu_9200.OnTime)
			jv, _ = sjson.Set(jv, "data.ct", svrmsg.WlstTml.WlstEsu_9200.OffTime)
			jv, _ = sjson.Set(jv, "data.ppc", svrmsg.WlstTml.WlstEsu_9200.PhaseCount)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x93, 0x9f: // 节能选测（短）
		svrmsg.WlstTml.WlstEsu_9300 = &msgctl.WlstEsu_9F00{}
		var k = 0
		if cmd == 0x9f {
			svrmsg.Head.Cmd = fmt.Sprintf("wlst.esu.%02x%02x", cmd, d[4])
			f.DataCmd = svrmsg.Head.Cmd
			k = 1
		}
		if cmd == 0x93 || (cmd == 0x9f && (d[4] == 1 || d[4] == 3)) {
			svrmsg.WlstTml.WlstEsu_9300.DateTime = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", int32(d[k+4])+2000, d[k+5], d[k+6], d[k+7], d[k+8], d[k+9])
			svrmsg.WlstTml.WlstEsu_9300.Temperature = int32(d[k+10])
			svrmsg.WlstTml.WlstEsu_9300.APhaseInputVoltage = (float64(d[k+11]) + float64(d[k+12])*256.0) / 100.0
			svrmsg.WlstTml.WlstEsu_9300.BPhaseInputVoltage = (float64(d[k+13]) + float64(d[k+14])*256.0) / 100.0
			svrmsg.WlstTml.WlstEsu_9300.CPhaseInputVoltage = (float64(d[k+15]) + float64(d[k+16])*256.0) / 100.0
			svrmsg.WlstTml.WlstEsu_9300.APhaseOutputVoltage = (float64(d[k+17]) + float64(d[k+18])*256.0) / 100.0
			svrmsg.WlstTml.WlstEsu_9300.BPhaseOutputVoltage = (float64(d[k+19]) + float64(d[k+20])*256.0) / 100.0
			svrmsg.WlstTml.WlstEsu_9300.CPhaseOutputVoltage = (float64(d[k+21]) + float64(d[k+22])*256.0) / 100.0
			svrmsg.WlstTml.WlstEsu_9300.APhaseOutputCurrent = (float64(d[k+23]) + float64(d[k+24])*256.0) / 100.0
			svrmsg.WlstTml.WlstEsu_9300.BPhaseOutputCurrent = (float64(d[k+25]) + float64(d[k+26])*256.0) / 100.0
			svrmsg.WlstTml.WlstEsu_9300.CPhaseOutputCurrent = (float64(d[k+27]) + float64(d[k+28])*256.0) / 100.0
			svrmsg.WlstTml.WlstEsu_9300.APhaseOutputPower = (float64(d[k+29]) + float64(d[k+30])*256.0) / 100.0
			svrmsg.WlstTml.WlstEsu_9300.BPhaseOutputPower = (float64(d[k+31]) + float64(d[k+32])*256.0) / 100.0
			svrmsg.WlstTml.WlstEsu_9300.CPhaseOutputPower = (float64(d[k+33]) + float64(d[k+34])*256.0) / 100.0
			if d[k+35] == 0x55 {
				svrmsg.WlstTml.WlstEsu_9300.FanStatus = 1
			} else {
				svrmsg.WlstTml.WlstEsu_9300.FanStatus = 0
			}
			switch d[k+36] {
			case 0:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 0
			case 1:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 1
			case 3:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 2
			case 5:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 3
			case 9:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 4
			case 0x0b:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 5
			case 0x15:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 6
			case 0x19:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 7
			case 0x1b:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 8
			case 0x25:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 9
			case 0x2b:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 10
			case 0x35:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 11
			case 0x3b:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 12
			case 0x45:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 13
			case 0x4b:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 14
			case 0x55:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 15
			case 0x5b:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 16
			case 0x65:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 17
			case 0x75:
				svrmsg.WlstTml.WlstEsu_9300.SaverStatus = 18
			}
			svrmsg.WlstTml.WlstEsu_9300.RunTime = int32(d[k+37]) + int32(d[k+38])*256
			svrmsg.WlstTml.WlstEsu_9300.SaverTime = int32(d[k+39]) + int32(d[k+40])*256
			svrmsg.WlstTml.WlstEsu_9300.AdjustValue = float64(int32(d[k+41])+int32(d[k+42])*256) / 100.0
			svrmsg.WlstTml.WlstEsu_9300.ExistingFault = gopsu.String2Int32(fmt.Sprintf("%08b%08b", d[k+44], d[k+43]), 2)
			if cmd == 0x9f && d[4] == 3 {
				k += 41
				svrmsg.WlstTml.WlstEsu_9300.ResetDay0 = int32(d[k+4])
				svrmsg.WlstTml.WlstEsu_9300.ResetDay1 = int32(d[k+5])
				svrmsg.WlstTml.WlstEsu_9300.ResetDay2 = int32(d[k+6])
				svrmsg.WlstTml.WlstEsu_9300.ResetDay3 = int32(d[k+7])
				svrmsg.WlstTml.WlstEsu_9300.ArgsStatus = gopsu.String2Int64(fmt.Sprintf("%08b%08b%08b%08b", d[k+11], d[k+10], d[k+9], d[k+8]), 2)
				svrmsg.WlstTml.WlstEsu_9300.SaverMode = int32(d[k+12])
				svrmsg.WlstTml.WlstEsu_9300.AdjustStalls = int32(d[k+13])
				svrmsg.WlstTml.WlstEsu_9300.AdjustTime = int32(d[k+14])
				svrmsg.WlstTml.WlstEsu_9300.AdjustA = int32(d[k+15])
				svrmsg.WlstTml.WlstEsu_9300.AdjustB = int32(d[k+16])
				svrmsg.WlstTml.WlstEsu_9300.AdjustC = int32(d[k+17])
				svrmsg.WlstTml.WlstEsu_9300.IgbtStatus = int32(d[k+18])
				svrmsg.WlstTml.WlstEsu_9300.IgbtTemperature = int32(d[k+19])
				svrmsg.WlstTml.WlstEsu_9300.EventNo = int32(d[k+20])
				svrmsg.WlstTml.WlstEsu_9300.SwitchOutStatus = int32(d[k+21])
				svrmsg.WlstTml.WlstEsu_9300.SwitchInStatus = int32(d[k+22])
				svrmsg.WlstTml.WlstEsu_9300.RunStatus = int32(d[k+23])
			}
		}
		if cmd == 0x9f && d[4] == 2 {
			svrmsg.WlstTml.WlstEsu_9300.ResetDay0 = int32(d[k+4])
			svrmsg.WlstTml.WlstEsu_9300.ResetDay1 = int32(d[k+5])
			svrmsg.WlstTml.WlstEsu_9300.ResetDay2 = int32(d[k+6])
			svrmsg.WlstTml.WlstEsu_9300.ResetDay3 = int32(d[k+7])
			svrmsg.WlstTml.WlstEsu_9300.ArgsStatus = gopsu.String2Int64(fmt.Sprintf("%08b%08b%08b%08b", d[k+11], d[k+10], d[k+9], d[k+8]), 2)
			svrmsg.WlstTml.WlstEsu_9300.SaverMode = int32(d[k+12])
			svrmsg.WlstTml.WlstEsu_9300.AdjustStalls = int32(d[k+13])
			svrmsg.WlstTml.WlstEsu_9300.AdjustTime = int32(d[k+14])
			svrmsg.WlstTml.WlstEsu_9300.AdjustA = int32(d[k+15])
			svrmsg.WlstTml.WlstEsu_9300.AdjustB = int32(d[k+16])
			svrmsg.WlstTml.WlstEsu_9300.AdjustC = int32(d[k+17])
			svrmsg.WlstTml.WlstEsu_9300.IgbtStatus = int32(d[k+18])
			svrmsg.WlstTml.WlstEsu_9300.IgbtTemperature = int32(d[k+19])
			svrmsg.WlstTml.WlstEsu_9300.EventNo = int32(d[k+20])
			svrmsg.WlstTml.WlstEsu_9300.SwitchOutStatus = int32(d[k+21])
			svrmsg.WlstTml.WlstEsu_9300.SwitchInStatus = int32(d[k+22])
			if d[k+23] == 0x55 {
				svrmsg.WlstTml.WlstEsu_9300.RunStatus = 1
			} else {
				svrmsg.WlstTml.WlstEsu_9300.RunStatus = 0
			}
		}
		zm := svrmsg.WlstTml.WlstEsu_9300
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			if cmd == 0x93 || (cmd == 0x9f && (d[4] == 1 || d[4] == 3)) {
				jv, _ = sjson.Set(jv, "data.date", svrmsg.WlstTml.WlstEsu_9300.DateTime)
				jv, _ = sjson.Set(jv, "data.tmp", svrmsg.WlstTml.WlstEsu_9300.Temperature)
				jv, _ = sjson.Set(jv, "data.avi", svrmsg.WlstTml.WlstEsu_9300.APhaseInputVoltage)
				jv, _ = sjson.Set(jv, "data.bvi", svrmsg.WlstTml.WlstEsu_9300.BPhaseInputVoltage)
				jv, _ = sjson.Set(jv, "data.cvi", svrmsg.WlstTml.WlstEsu_9300.CPhaseInputVoltage)
				jv, _ = sjson.Set(jv, "data.avo", svrmsg.WlstTml.WlstEsu_9300.APhaseOutputVoltage)
				jv, _ = sjson.Set(jv, "data.bvo", svrmsg.WlstTml.WlstEsu_9300.BPhaseOutputVoltage)
				jv, _ = sjson.Set(jv, "data.cvo", svrmsg.WlstTml.WlstEsu_9300.CPhaseOutputVoltage)
				jv, _ = sjson.Set(jv, "data.aao", svrmsg.WlstTml.WlstEsu_9300.APhaseOutputCurrent)
				jv, _ = sjson.Set(jv, "data.bao", svrmsg.WlstTml.WlstEsu_9300.BPhaseOutputCurrent)
				jv, _ = sjson.Set(jv, "data.cao", svrmsg.WlstTml.WlstEsu_9300.CPhaseOutputCurrent)
				jv, _ = sjson.Set(jv, "data.apo", svrmsg.WlstTml.WlstEsu_9300.APhaseOutputPower)
				jv, _ = sjson.Set(jv, "data.bpo", svrmsg.WlstTml.WlstEsu_9300.BPhaseOutputPower)
				jv, _ = sjson.Set(jv, "data.cpo", svrmsg.WlstTml.WlstEsu_9300.CPhaseOutputPower)
				jv, _ = sjson.Set(jv, "data.fs", svrmsg.WlstTml.WlstEsu_9300.FanStatus)
				jv, _ = sjson.Set(jv, "data.st", svrmsg.WlstTml.WlstEsu_9300.SaverStatus)
				jv, _ = sjson.Set(jv, "data.ort", svrmsg.WlstTml.WlstEsu_9300.RunTime)
				jv, _ = sjson.Set(jv, "data.crt", svrmsg.WlstTml.WlstEsu_9300.SaverTime)
				jv, _ = sjson.Set(jv, "data.curv", svrmsg.WlstTml.WlstEsu_9300.AdjustValue)
				jv, _ = sjson.Set(jv, "data.err", svrmsg.WlstTml.WlstEsu_9300.ExistingFault)

				if cmd == 0x9f && d[4] == 3 {
					jv, _ = sjson.Set(jv, "data.red0", svrmsg.WlstTml.WlstEsu_9300.ResetDay0)
					jv, _ = sjson.Set(jv, "data.red1", svrmsg.WlstTml.WlstEsu_9300.ResetDay1)
					jv, _ = sjson.Set(jv, "data.red2", svrmsg.WlstTml.WlstEsu_9300.ResetDay2)
					jv, _ = sjson.Set(jv, "data.red3", svrmsg.WlstTml.WlstEsu_9300.ResetDay3)
					jv, _ = sjson.Set(jv, "data.arg", svrmsg.WlstTml.WlstEsu_9300.ArgsStatus)
					jv, _ = sjson.Set(jv, "data.esm", svrmsg.WlstTml.WlstEsu_9300.SaverMode)
					jv, _ = sjson.Set(jv, "data.curs", svrmsg.WlstTml.WlstEsu_9300.AdjustStalls)
					jv, _ = sjson.Set(jv, "data.curt", svrmsg.WlstTml.WlstEsu_9300.AdjustTime)
					jv, _ = sjson.Set(jv, "data.cura", svrmsg.WlstTml.WlstEsu_9300.AdjustA)
					jv, _ = sjson.Set(jv, "data.curb", svrmsg.WlstTml.WlstEsu_9300.AdjustB)
					jv, _ = sjson.Set(jv, "data.curc", svrmsg.WlstTml.WlstEsu_9300.AdjustC)
					jv, _ = sjson.Set(jv, "data.igbtst", svrmsg.WlstTml.WlstEsu_9300.IgbtStatus)
					jv, _ = sjson.Set(jv, "data.igbttmp", svrmsg.WlstTml.WlstEsu_9300.IgbtTemperature)
					jv, _ = sjson.Set(jv, "data.no", svrmsg.WlstTml.WlstEsu_9300.EventNo)
					jv, _ = sjson.Set(jv, "data.lout", svrmsg.WlstTml.WlstEsu_9300.SwitchOutStatus)
					jv, _ = sjson.Set(jv, "data.lin", svrmsg.WlstTml.WlstEsu_9300.SwitchInStatus)
					jv, _ = sjson.Set(jv, "data.rst", svrmsg.WlstTml.WlstEsu_9300.RunStatus)
				}
			}
			if cmd == 0x9f && d[4] == 2 {
				jv, _ = sjson.Set(jv, "data.red0", svrmsg.WlstTml.WlstEsu_9300.ResetDay0)
				jv, _ = sjson.Set(jv, "data.red1", svrmsg.WlstTml.WlstEsu_9300.ResetDay1)
				jv, _ = sjson.Set(jv, "data.red2", svrmsg.WlstTml.WlstEsu_9300.ResetDay2)
				jv, _ = sjson.Set(jv, "data.red3", svrmsg.WlstTml.WlstEsu_9300.ResetDay3)
				jv, _ = sjson.Set(jv, "data.arg", svrmsg.WlstTml.WlstEsu_9300.ArgsStatus)
				jv, _ = sjson.Set(jv, "data.esm", svrmsg.WlstTml.WlstEsu_9300.SaverMode)
				jv, _ = sjson.Set(jv, "data.curs", svrmsg.WlstTml.WlstEsu_9300.AdjustStalls)
				jv, _ = sjson.Set(jv, "data.curt", svrmsg.WlstTml.WlstEsu_9300.AdjustTime)
				jv, _ = sjson.Set(jv, "data.cura", svrmsg.WlstTml.WlstEsu_9300.AdjustA)
				jv, _ = sjson.Set(jv, "data.curb", svrmsg.WlstTml.WlstEsu_9300.AdjustB)
				jv, _ = sjson.Set(jv, "data.curc", svrmsg.WlstTml.WlstEsu_9300.AdjustC)
				jv, _ = sjson.Set(jv, "data.igbtst", svrmsg.WlstTml.WlstEsu_9300.IgbtStatus)
				jv, _ = sjson.Set(jv, "data.igbttmp", svrmsg.WlstTml.WlstEsu_9300.IgbtTemperature)
				jv, _ = sjson.Set(jv, "data.no", svrmsg.WlstTml.WlstEsu_9300.EventNo)
				jv, _ = sjson.Set(jv, "data.lout", svrmsg.WlstTml.WlstEsu_9300.SwitchOutStatus)
				jv, _ = sjson.Set(jv, "data.lin", svrmsg.WlstTml.WlstEsu_9300.SwitchInStatus)
				jv, _ = sjson.Set(jv, "data.rst", svrmsg.WlstTml.WlstEsu_9300.RunStatus)
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x95: // 节能时间招测
		svrmsg.WlstTml.WlstEsu_9500 = &msgctl.WlstEsu_9500{}
		for i := 0; i < 32; i += 4 {
			if d[i+4] < 24 && d[i+5] < 60 {
				svrmsg.WlstTml.WlstEsu_9500.XAdjustTime = append(svrmsg.WlstTml.WlstEsu_9500.XAdjustTime, int32(d[i+4])*60+int32(d[i+5]))
				svrmsg.WlstTml.WlstEsu_9500.XAdjustValue = append(svrmsg.WlstTml.WlstEsu_9500.XAdjustValue, (int32(d[i+6])+int32(d[i+7])*256)/100)
			} else {
				svrmsg.WlstTml.WlstEsu_9500.XAdjustTime = append(svrmsg.WlstTml.WlstEsu_9500.XAdjustTime, 0)
				svrmsg.WlstTml.WlstEsu_9500.XAdjustValue = append(svrmsg.WlstTml.WlstEsu_9500.XAdjustValue, 0)
			}
		}
		zm := svrmsg.WlstTml.WlstEsu_9500
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			for i := 0; i < 32; i = i + 4 {
				if d[i+4] < 24 && d[i+5] < 60 {
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.t%d", i/4+1), int32(d[i+4])*60+int32(d[i+5]))
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.v%d", i/4+1), (int32(d[i+6])+int32(d[i+7])*256)/100)
				} else {
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.t%d", i/4+1), 0)
					jv, _ = sjson.Set(jv, fmt.Sprintf("data.v%d", i/4+1), 0)
				}
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x97: // 节能事件招测
		svrmsg.WlstTml.WlstEsu_9700 = &msgctl.WlstEsu_9700{}
		svrmsg.WlstTml.WlstEsu_9700.No = int32(d[4])
		svrmsg.WlstTml.WlstEsu_9700.DateTime = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", int32(d[5])+2000, d[6], d[7], d[8], d[9], d[10])
		svrmsg.WlstTml.WlstEsu_9700.AdjustValue = (float64(d[11]) + float64(d[12])*256.0) / 100.0
		svrmsg.WlstTml.WlstEsu_9700.APhaseInputVoltage = (float64(d[13]) + float64(d[14])*256.0) / 100.0
		svrmsg.WlstTml.WlstEsu_9700.BPhaseInputVoltage = (float64(d[15]) + float64(d[16])*256.0) / 100.0
		svrmsg.WlstTml.WlstEsu_9700.CPhaseInputVoltage = (float64(d[17]) + float64(d[18])*256.0) / 100.0
		svrmsg.WlstTml.WlstEsu_9700.APhaseOutputVoltage = (float64(d[19]) + float64(d[20])*256.0) / 100.0
		svrmsg.WlstTml.WlstEsu_9700.BPhaseOutputVoltage = (float64(d[21]) + float64(d[22])*256.0) / 100.0
		svrmsg.WlstTml.WlstEsu_9700.CPhaseOutputVoltage = (float64(d[23]) + float64(d[24])*256.0) / 100.0
		svrmsg.WlstTml.WlstEsu_9700.APhaseOutputCurrent = (float64(d[25]) + float64(d[26])*256.0) / 100.0
		svrmsg.WlstTml.WlstEsu_9700.BPhaseOutputCurrent = (float64(d[27]) + float64(d[28])*256.0) / 100.0
		svrmsg.WlstTml.WlstEsu_9700.CPhaseOutputCurrent = (float64(d[29]) + float64(d[30])*256.0) / 100.0
		svrmsg.WlstTml.WlstEsu_9700.SaverTime = int32(d[31]) + int32(d[32])*256
		switch d[33] {
		case 0:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 0
		case 1:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 1
		case 3:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 2
		case 5:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 3
		case 9:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 4
		case 0x0b:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 5
		case 0x15:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 6
		case 0x19:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 7
		case 0x1b:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 8
		case 0x25:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 9
		case 0x2b:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 10
		case 0x35:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 11
		case 0x3b:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 12
		case 0x45:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 13
		case 0x4b:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 14
		case 0x55:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 15
		case 0x5b:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 16
		case 0x65:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 17
		case 0x75:
			svrmsg.WlstTml.WlstEsu_9700.SaverStatus = 18
		}
		svrmsg.WlstTml.WlstEsu_9700.Temperature = int32(d[34])
		switch d[35] {
		case 0:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 0
		case 1:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 1
		case 3:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 2
		case 5:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 3
		case 9:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 4
		case 0x0b:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 5
		case 0x15:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 6
		case 0x19:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 7
		case 0x1b:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 8
		case 0x25:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 9
		case 0x2b:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 10
		case 0x35:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 11
		case 0x3b:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 12
		case 0x45:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 13
		case 0x4b:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 14
		case 0x55:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 15
		case 0x5b:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 16
		case 0x65:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 17
		case 0x75:
			svrmsg.WlstTml.WlstEsu_9700.EventType = 18
		}
		svrmsg.WlstTml.WlstEsu_9700.InfoNumber = int32(d[36])
		zm := svrmsg.WlstTml.WlstEsu_9700
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.no", svrmsg.WlstTml.WlstEsu_9700.No)
			jv, _ = sjson.Set(jv, "data.date", svrmsg.WlstTml.WlstEsu_9700.DateTime)
			jv, _ = sjson.Set(jv, "data.tv", svrmsg.WlstTml.WlstEsu_9700.AdjustValue)
			jv, _ = sjson.Set(jv, "data.avi", svrmsg.WlstTml.WlstEsu_9700.APhaseInputVoltage)
			jv, _ = sjson.Set(jv, "data.bvi", svrmsg.WlstTml.WlstEsu_9700.BPhaseInputVoltage)
			jv, _ = sjson.Set(jv, "data.cvi", svrmsg.WlstTml.WlstEsu_9700.CPhaseInputVoltage)
			jv, _ = sjson.Set(jv, "data.avo", svrmsg.WlstTml.WlstEsu_9700.APhaseOutputVoltage)
			jv, _ = sjson.Set(jv, "data.bvo", svrmsg.WlstTml.WlstEsu_9700.BPhaseOutputVoltage)
			jv, _ = sjson.Set(jv, "data.cvo", svrmsg.WlstTml.WlstEsu_9700.CPhaseOutputVoltage)
			jv, _ = sjson.Set(jv, "data.aao", svrmsg.WlstTml.WlstEsu_9700.APhaseOutputCurrent)
			jv, _ = sjson.Set(jv, "data.bao", svrmsg.WlstTml.WlstEsu_9700.BPhaseOutputCurrent)
			jv, _ = sjson.Set(jv, "data.cao", svrmsg.WlstTml.WlstEsu_9700.CPhaseOutputCurrent)
			jv, _ = sjson.Set(jv, "data.crt", svrmsg.WlstTml.WlstEsu_9700.SaverTime)
			jv, _ = sjson.Set(jv, "data.st", svrmsg.WlstTml.WlstEsu_9700.SaverStatus)
			jv, _ = sjson.Set(jv, "data.tmp", svrmsg.WlstTml.WlstEsu_9700.Temperature)
			jv, _ = sjson.Set(jv, "data.et", svrmsg.WlstTml.WlstEsu_9700.EventType)
			jv, _ = sjson.Set(jv, "data.info", svrmsg.WlstTml.WlstEsu_9700.InfoNumber)

			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x9a: // 招测运行时间记录
		svrmsg.WlstTml.WlstEsu_9A00 = &msgctl.WlstEsu_9A00{}
		svrmsg.WlstTml.WlstEsu_9A00.No = int32(d[4])
		svrmsg.WlstTml.WlstEsu_9A00.DateTime = fmt.Sprintf("%04d-%02d-%02d", int32(d[5])+int32(d[6])*256, d[7], d[8])
		svrmsg.WlstTml.WlstEsu_9A00.RunTime = int32(d[9]) + int32(d[10])*256
		svrmsg.WlstTml.WlstEsu_9A00.SaverTime = int32(d[11]) + int32(d[12])*256
		zm := svrmsg.WlstTml.WlstEsu_9A00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.no", svrmsg.WlstTml.WlstEsu_9A00.No)
			jv, _ = sjson.Set(jv, "data.date", svrmsg.WlstTml.WlstEsu_9A00.DateTime)
			jv, _ = sjson.Set(jv, "data.ort", svrmsg.WlstTml.WlstEsu_9A00.RunTime)
			jv, _ = sjson.Set(jv, "data.crt", svrmsg.WlstTml.WlstEsu_9A00.SaverTime)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x9b: // 招测版本号
		svrmsg.WlstTml.WlstEsu_9B00 = &msgctl.WlstRtuDc00{}
		svrmsg.WlstTml.WlstEsu_9B00.Ver = string(d[4:24])
		zm := svrmsg.WlstTml.WlstEsu_9B00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.ver", svrmsg.WlstTml.WlstEsu_9B00.Ver)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x9e: // 招测工作参数
		svrmsg.WlstTml.WlstEsu_9E00 = &msgctl.WlstEsu_9E00{}
		svrmsg.WlstTml.WlstEsu_9E00.WarmupTime = int32(d[4])
		svrmsg.WlstTml.WlstEsu_9E00.OnTime = int32(d[5])*60 + int32(d[6])
		svrmsg.WlstTml.WlstEsu_9E00.OffTime = int32(d[7])*60 + int32(d[8])
		svrmsg.WlstTml.WlstEsu_9E00.TransformerA = int32(d[9]) * 5
		svrmsg.WlstTml.WlstEsu_9E00.TransformerB = int32(d[10]) * 5
		svrmsg.WlstTml.WlstEsu_9E00.TransformerC = int32(d[11]) * 5
		if d[12] == 0x55 {
			svrmsg.WlstTml.WlstEsu_9E00.TimeMode = 1
		} else {
			svrmsg.WlstTml.WlstEsu_9E00.TimeMode = 0
		}
		svrmsg.WlstTml.WlstEsu_9E00.RunMode = int32(d[13])
		svrmsg.WlstTml.WlstEsu_9E00.FanStartTemperature = int32(d[14])
		svrmsg.WlstTml.WlstEsu_9E00.FanStopTemperature = int32(d[15])
		svrmsg.WlstTml.WlstEsu_9E00.SaverStopTemperature = int32(d[16])
		svrmsg.WlstTml.WlstEsu_9E00.SaverRecoverTemperature = int32(d[17])
		svrmsg.WlstTml.WlstEsu_9E00.ProtectionTemperature = int32(d[18])
		svrmsg.WlstTml.WlstEsu_9E00.InputOvervoltage = (int32(d[19]) + int32(d[20])*256) / 100
		svrmsg.WlstTml.WlstEsu_9E00.InputUndervoltage = (int32(d[21]) + int32(d[22])*256) / 100
		svrmsg.WlstTml.WlstEsu_9E00.OutputOverload = (int32(d[23]) + int32(d[24])*256) / 100
		svrmsg.WlstTml.WlstEsu_9E00.OutputUndervoltage = (int32(d[25]) + int32(d[26])*256) / 100
		svrmsg.WlstTml.WlstEsu_9E00.AdjustSpeed = int32(d[27])
		svrmsg.WlstTml.WlstEsu_9E00.PhaseCount = int32(d[28])
		if d[29] == 0x55 {
			svrmsg.WlstTml.WlstEsu_9E00.CommunicateMode = 1
		} else {
			svrmsg.WlstTml.WlstEsu_9E00.CommunicateMode = 0
		}
		if d[30] == 0x55 {
			svrmsg.WlstTml.WlstEsu_9E00.WorkMode = 1
		} else {
			svrmsg.WlstTml.WlstEsu_9E00.WorkMode = 0
		}
		if d[31] == 0x55 {
			svrmsg.WlstTml.WlstEsu_9E00.AlarmOn = 1
		} else {
			svrmsg.WlstTml.WlstEsu_9E00.AlarmOn = 0
		}
		svrmsg.WlstTml.WlstEsu_9E00.AlarmDelay = int32(d[32])
		if d[33] == 0x55 {
			svrmsg.WlstTml.WlstEsu_9E00.SaverMode = 0
		} else {
			svrmsg.WlstTml.WlstEsu_9E00.SaverMode = 1
		}
		zm := svrmsg.WlstTml.WlstEsu_9E00
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			jv, _ = sjson.Set(jv, "data.wt", svrmsg.WlstTml.WlstEsu_9E00.WarmupTime)
			jv, _ = sjson.Set(jv, "data.ot", svrmsg.WlstTml.WlstEsu_9E00.OnTime)
			jv, _ = sjson.Set(jv, "data.ct", svrmsg.WlstTml.WlstEsu_9E00.OffTime)
			jv, _ = sjson.Set(jv, "data.act", svrmsg.WlstTml.WlstEsu_9E00.TransformerA)
			jv, _ = sjson.Set(jv, "data.bct", svrmsg.WlstTml.WlstEsu_9E00.TransformerB)
			jv, _ = sjson.Set(jv, "data.cct", svrmsg.WlstTml.WlstEsu_9E00.TransformerC)
			jv, _ = sjson.Set(jv, "data.tt", svrmsg.WlstTml.WlstEsu_9E00.TimeMode)
			jv, _ = sjson.Set(jv, "data.rt", svrmsg.WlstTml.WlstEsu_9E00.RunMode)
			jv, _ = sjson.Set(jv, "data.stmp", svrmsg.WlstTml.WlstEsu_9E00.FanStartTemperature)
			jv, _ = sjson.Set(jv, "data.ctmp", svrmsg.WlstTml.WlstEsu_9E00.FanStopTemperature)
			jv, _ = sjson.Set(jv, "data.etmp", svrmsg.WlstTml.WlstEsu_9E00.SaverStopTemperature)
			jv, _ = sjson.Set(jv, "data.ptmp", svrmsg.WlstTml.WlstEsu_9E00.SaverRecoverTemperature)
			jv, _ = sjson.Set(jv, "data.rtmp", svrmsg.WlstTml.WlstEsu_9E00.ProtectionTemperature)
			jv, _ = sjson.Set(jv, "data.iovl", svrmsg.WlstTml.WlstEsu_9E00.InputOvervoltage)
			jv, _ = sjson.Set(jv, "data.iuvl", svrmsg.WlstTml.WlstEsu_9E00.InputUndervoltage)
			jv, _ = sjson.Set(jv, "data.oovl", svrmsg.WlstTml.WlstEsu_9E00.OutputOverload)
			jv, _ = sjson.Set(jv, "data.ouvl", svrmsg.WlstTml.WlstEsu_9E00.OutputUndervoltage)
			jv, _ = sjson.Set(jv, "data.sr", svrmsg.WlstTml.WlstEsu_9E00.AdjustSpeed)
			jv, _ = sjson.Set(jv, "data.ppc", svrmsg.WlstTml.WlstEsu_9E00.PhaseCount)
			jv, _ = sjson.Set(jv, "data.cm", svrmsg.WlstTml.WlstEsu_9E00.CommunicateMode)
			jv, _ = sjson.Set(jv, "data.om", svrmsg.WlstTml.WlstEsu_9E00.WorkMode)
			jv, _ = sjson.Set(jv, "data.aa", svrmsg.WlstTml.WlstEsu_9E00.AlarmOn)
			jv, _ = sjson.Set(jv, "data.ad", svrmsg.WlstTml.WlstEsu_9E00.AlarmDelay)
			jv, _ = sjson.Set(jv, "data.esm", svrmsg.WlstTml.WlstEsu_9E00.SaverMode)
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	case 0x90, 0x91, 0x96, 0x98, 0x99, 0x94, 0x9d, 0xa2, 0xa3:
		var ans int32
		if d[4] == 0x55 {
			ans = 1
		} else {
			ans = 0
		}
		switch cmd {
		case 0x94:
			svrmsg.WlstTml.WlstEsu_9400 = &msgctl.WlstEsu_9400{}
			svrmsg.WlstTml.WlstEsu_9400.Status = ans
		case 0x91:
			svrmsg.WlstTml.WlstEsu_9100 = &msgctl.WlstEsu_9000{}
			svrmsg.WlstTml.WlstEsu_9100.Status = ans
		case 0x96:
			svrmsg.WlstTml.WlstEsu_9600 = &msgctl.WlstEsu_9000{}
			svrmsg.WlstTml.WlstEsu_9600.Status = ans
		case 0x98:
			svrmsg.WlstTml.WlstEsu_9800 = &msgctl.WlstEsu_9000{}
			svrmsg.WlstTml.WlstEsu_9800.Status = ans
		case 0x99:
			svrmsg.WlstTml.WlstEsu_9900 = &msgctl.WlstEsu_9000{}
			svrmsg.WlstTml.WlstEsu_9900.Status = ans
		case 0x9d:
			svrmsg.WlstTml.WlstEsu_9D00 = &msgctl.WlstEsu_9000{}
			svrmsg.WlstTml.WlstEsu_9D00.Status = ans
		case 0xa2:
			svrmsg.WlstTml.WlstEsuA200 = &msgctl.WlstEsu_9000{}
			svrmsg.WlstTml.WlstEsuA200.Status = ans
		case 0xa3:
			svrmsg.WlstTml.WlstEsuA300 = &msgctl.WlstEsu_9000{}
			svrmsg.WlstTml.WlstEsuA300.Status = ans
		}
		zm := svrmsg.Head
		b, ex := pb2.Marshal(zm)
		if ex == nil {
			f.DataMQ = b
		}
		if AnsJSON {
			jv, _ := sjson.Set(JSONData, "head.cmd", f.DataCmd)
			jv, _ = sjson.Set(jv, "head.tra", tra)
			jv, _ = sjson.Set(jv, "args.addr.-1", f.Addr)
			jv, _ = sjson.Set(jv, "args.ip.-1", *ip)
			jv, _ = sjson.Set(jv, "args.port", *portlocal)
			if d[4] == 0x55 {
				jv, _ = sjson.Set(jv, "data.st", 1)
			} else {
				jv, _ = sjson.Set(jv, "data.st", 0)
			}
			ffj := &Fwd{
				DataCmd:  svrmsg.Head.Cmd,
				DataType: DataTypeString,
				DataDst:  "2",
				DstType:  SockData,
				Tra:      tra,
				Job:      JobSend,
				DataMsg:  []byte(jv),
			}
			lstf = append(lstf, ffj)
		}
	default:
		f.Ex = fmt.Sprintf("Unhandled ldu protocol: %s", gopsu.Bytes2String(d, "-"))
		lstf = append(lstf, f)
		return lstf
	}
	if len(f.DataCmd) > 0 {
		f.DataCmd = svrmsg.Head.Cmd
		f.DataMsg = CodePb2(svrmsg)
		lstf = append(lstf, f)
	}

	return lstf
}

// 远程升级
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
//  tra：是否485数据1-非485,2-485
//  tmladdr: 为485数据时，父设备物理地址
// Return:
// 	lstf: 处理反馈结果
func dataUpgrade(d []byte, ip *int64, portlocal *int, oldaddr int64) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "6",
		DstType:  SockData,
		Tra:      TraDirect,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}
	if !gopsu.CheckCrc16VB(d) {
		f.Ex = fmt.Sprintf("Rtu data validation fails")
		lstf = append(lstf, f)
		return lstf
	}
	var cmd, ll int32
	cmd = int32(d[6])
	ll = int32(d[3])*256 + int32(d[2])
	if oldaddr == 0 {
		f.Addr = int64(d[5])*256 + int64(d[4])
	} else {
		f.Addr = oldaddr
	}
	svrmsg := initMsgCtl(fmt.Sprintf("wlst.rtu.fe%02x", cmd), f.Addr, *ip, 1, 1, 1, portlocal)
	f.DataCmd = svrmsg.Head.Cmd
	switch cmd {
	case 0x81: // 升级完成主动上报
		svrmsg.WlstTml.WlstRtu_7081 = &msgctl.WlstRtu_7081{}
		svrmsg.WlstTml.WlstRtu_7081.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstRtu_7081.Status = int32(d[8])
		svrmsg.WlstTml.WlstRtu_7081.OldVer = string(d[9:29])
		svrmsg.WlstTml.WlstRtu_7081.NewVer = string(d[29:49])
		svrmsg.WlstTml.WlstRtu_7081.DataLocation = int32(d[49])
	case 0x85: // 查询版本应答
		svrmsg.WlstTml.WlstRtu_7085 = &msgctl.WlstRtu_7081{}
		svrmsg.WlstTml.WlstRtu_7085.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstRtu_7085.Status = int32(d[8])
		svrmsg.WlstTml.WlstRtu_7085.OldVer = string(d[11:31])
	case 0x86: // 升级准备应答
		svrmsg.WlstTml.WlstRtu_7086 = &msgctl.WlstRtu_7081{}
		svrmsg.WlstTml.WlstRtu_7086.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstRtu_7086.Status = int32(d[8])
	case 0x87: // 升级包状态查询应答
		svrmsg.WlstTml.WlstRtu_7087 = &msgctl.WlstRtu_7087{}
		svrmsg.WlstTml.WlstRtu_7087.CmdIdx = int32(d[7])
		svrmsg.WlstTml.WlstRtu_7087.Status = int32(d[8])
		if d[8] > 0 { // 失败需补发
			var s string
			for i := int32(9); i < ll-5+9; i++ {
				s = fmt.Sprintf("%08b", d[i]) + s
			}
			s = gopsu.ReverseString(s)
			for k, v := range s {
				if v == 48 {
					svrmsg.WlstTml.WlstRtu_7087.FailedPackages = append(svrmsg.WlstTml.WlstRtu_7087.FailedPackages, int32(k))
				}
			}
		}
	case 0x88: // 升级包发送应答（无视）
		f.DataCmd = ""
	default:
		f.Ex = fmt.Sprintf("Unhandled upgrade protocol: %s", gopsu.Bytes2String(d, "-"))
		lstf = append(lstf, f)
		return lstf
	}

	if len(f.DataCmd) > 0 {
		f.DataMsg = CodePb2(svrmsg)
		lstf = append(lstf, f)
	}

	return lstf
}
