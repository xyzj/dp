package v6

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/xyzj/gopsu"
	msgctl "gitlab.local/proto/msgjk"
	msgopen "gitlab.local/proto/msgwlst"
)

// PrepareCtl 自有协议数据预处理
func (dp *DataProcessor) PrepareCtl(b *[]byte) (lstf []*Fwd) {
	defer func() {
		if ex := recover(); ex != nil {
			f := &Fwd{
				Ex: fmt.Sprintf("%+v", errors.WithStack(ex.(error))),
			}
			lstf = append(lstf, f)
		}
	}()
	var pb2data *msgctl.MsgWithCtrl
	err := pb2data.Unmarshal(*b)
	if err != nil {
		panic(err.Error())
	}

	scmd := strings.Split(pb2data.Head.Cmd, ".")
	var xaddrs []int64
	if pb2data.Args != nil {
		if len(pb2data.Args.Addr) > 0 {
			xaddrs = make([]int64, 0, len(pb2data.Args.Addr))
			xaddrs = append(xaddrs, pb2data.Args.Addr...)
		} else {
			xaddrs = make([]int64, 0, len(pb2data.Args.Saddr))
			for _, v := range pb2data.Args.Saddr {
				if len(v) > 0 {
					if strings.Contains(v, "-") {
						s := strings.Split(v, "-")
						for i := gopsu.String2Int64(s[0], 10); i <= gopsu.String2Int64(s[1], 10); i++ {
							xaddrs = append(xaddrs, i)
						}
					} else {
						xaddrs = append(xaddrs, gopsu.String2Int64(v, 10))
					}
				}
			}
		}
	}
	if len(xaddrs) == 0 {
		f := &Fwd{
			Ex: "no tml addr set",
		}
		lstf = append(lstf, f)
		return lstf
	}
	if pb2data.Head.Tver == 2 {
		scmd[1] = "rtu"
	}
	for _, v := range xaddrs {
		f := &Fwd{
			DataSrc: b,
			Job:     1,
			DataDst: fmt.Sprintf("%s-%d", strings.Join(scmd[:2], "-"), v),
		}
		lstf = append(lstf, f)
	}
	return lstf
}

// PrepareOpen 自有协议数据预处理
func (dp *DataProcessor) PrepareOpen(b *[]byte) (lstf []*Fwd) {
	defer func() {
		if ex := recover(); ex != nil {
			f := &Fwd{
				Ex: fmt.Sprintf("%+v", errors.WithStack(ex.(error))),
			}
			lstf = append(lstf, f)
		}
	}()
	var pb2data *msgopen.MsgGBOpen
	err := pb2data.Unmarshal(*b)
	if err != nil {
		panic(err.Error())
	}

	f := &Fwd{
		DataCmd: fmt.Sprintf("wlst-open-%02x%02x", pb2data.DataID.Fun, pb2data.DataID.Afn),
		DataSrc: b,
		Job:     1,
		DataSP:  byte(pb2data.DataID.Sp),
		DataDst: fmt.Sprintf("wlst-open-%d-%s", pb2data.DataID.Addr, pb2data.DataID.Area),
	}
	lstf = append(lstf, f)
	return lstf
}

// ProcessCtl 处理五零盛同 msgwithctrl数据
func (dp *DataProcessor) ProcessCtl(b *[]byte) (lstf []*Fwd) {
	defer func() {
		if ex := recover(); ex != nil {
			f := &Fwd{
				Ex: fmt.Sprintf("%+v", errors.WithStack(ex.(error))),
			}
			lstf = append(lstf, f)
		}
	}()
	var pb2data *msgctl.MsgWithCtrl
	err := pb2data.Unmarshal(*b)
	if err != nil {
		panic(err.Error())
	}

	var ndata []byte
	var ndatacmd string

	getprotocol := true
	cmd := pb2data.Head.Cmd
	tra := byte(pb2data.Head.Tra)
	var br, rc byte

	switch pb2data.Head.Ver {
	case 1:
		switch pb2data.Head.Mod {
		case 1:
			if strings.HasSuffix(pb2data.Head.Cmd, "socketclose") {
				for _, v := range pb2data.Args.Addr {
					f := &Fwd{
						DataCmd: pb2data.Head.Cmd,
						DataDst: fmt.Sprintf("%s-%d", strings.Join(strings.Split(pb2data.Head.Cmd, ".")[:2], "-"), v),
						Job:     JobSend,
						Src:     fmt.Sprintf("%v", pb2data),
						DstType: byte(pb2data.Head.Src),
						DstIMEI: v,
						// DataMsg: strings.Join(pb2data.Args.Saddr, ","),
					}
					lstf = append(lstf, f)
				}
			}
		case 2:
			scmd := strings.Split(pb2data.Head.Cmd, ".")
			var xaddrs []int64
			if pb2data.Args != nil {
				if len(pb2data.Args.Addr) > 0 {
					xaddrs = make([]int64, 0, len(pb2data.Args.Addr))
					xaddrs = append(xaddrs, pb2data.Args.Addr...)
				} else {
					xaddrs = make([]int64, 0, len(pb2data.Args.Saddr))
					for _, v := range pb2data.Args.Saddr {
						if len(v) > 0 {
							if strings.Contains(v, "-") {
								s := strings.Split(v, "-")
								for i := gopsu.String2Int64(s[0], 10); i <= gopsu.String2Int64(s[1], 10); i++ {
									xaddrs = append(xaddrs, i)
								}
							} else {
								xaddrs = append(xaddrs, gopsu.String2Int64(v, 10))
							}
						}
					}
				}
			}
			if len(xaddrs) == 0 {
				f := &Fwd{
					Ex: "no tml addr set",
				}
				lstf = append(lstf, f)
				return lstf
			}
			switch pb2data.Head.Src {
			case 2, 5, 6, 7:
				var d bytes.Buffer
				switch scmd[0] {
				case "wlst":
					switch scmd[1] {
					case "slu", "vslu", "nbslu": // 单灯
						br = 5
						rc = 0
						switch scmd[2] {
						case "1900": // 复位网络
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_1900.DoFlag))
						case "7800": // 事件招测
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7800.CmdIdx))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7800.EventType + 0x20))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7800.ClassType))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7800.RecordCount))
							y, m, dd, h, mm, s, _ := gopsu.SplitDateTime(pb2data.WlstTml.WlstSlu_7800.DtStart)
							d.Write([]byte{y, m, dd, h, mm, s})
						case "6c00": // 读取节假日参数
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_6C00.CmdIdx))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_6C00.StartIdx))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_6C00.ReadCount))
						case "6b00": // 设置节假日控制
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_6B00.CmdIdx))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_6B00.SetIdx))
							_, m, dd, h, _, _, _ := gopsu.SplitDateTime(pb2data.WlstTml.WlstSlu_6B00.DtStart)
							d.WriteByte(m)
							d.WriteByte(dd)
							d.WriteByte(h)
							_, m, dd, h, _, _, _ = gopsu.SplitDateTime(pb2data.WlstTml.WlstSlu_6B00.DtEnd)
							d.WriteByte(m)
							d.WriteByte(dd)
							d.WriteByte(h)
							mm := fmt.Sprintf("%04b%04b", pb2data.WlstTml.WlstSlu_6B00.OperationOrder, pb2data.WlstTml.WlstSlu_6B00.OperationType)
							d.WriteByte(gopsu.String2Int8(mm, 2))
							switch pb2data.WlstTml.WlstSlu_6B00.OperationType {
							case 1:
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_6B00.TimerOrOffset / 60))
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_6B00.TimerOrOffset % 60))
							case 2:
								if pb2data.WlstTml.WlstSlu_6B00.TimerOrOffset < 0 {
									mm = fmt.Sprintf("1%015b", 0-pb2data.WlstTml.WlstSlu_6B00.TimerOrOffset)
								} else {
									mm = fmt.Sprintf("0%015b", pb2data.WlstTml.WlstSlu_6B00.TimerOrOffset)
								}
								d.WriteByte(gopsu.String2Int8(mm[8:], 2))
								d.WriteByte(gopsu.String2Int8(mm[:8], 2))
							}
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_6B00.CmdType))
							switch pb2data.WlstTml.WlstSlu_6B00.CmdType {
							case 3:
								for _, v := range pb2data.WlstTml.WlstSlu_6B00.CmdMix {
									if v < 4 {
										d.WriteByte(1)
									} else {
										d.WriteByte(0)
									}
								}
							case 4:
								if len(pb2data.WlstTml.WlstSlu_6B00.CmdMix) == 0 {
									d.Write([]byte{0, 0, 0, 0})
								}
								for k, v := range pb2data.WlstTml.WlstSlu_6B00.CmdMix {
									if k > 3 {
										break
									}
									switch v {
									case 0:
										d.WriteByte(0)
									case 1:
										d.WriteByte(0x33)
									case 2:
										d.WriteByte(0x55)
									case 3:
										d.WriteByte(0xaa)
									case 4:
										d.WriteByte(0xcc)
									}
								}
							case 5:
								m := []string{"1", "1", "1", "1", "1", "1", "1", "1"}
								for _, v := range pb2data.WlstTml.WlstSlu_6B00.CmdPwm.LoopCanDo {
									if v > 8 || v < 1 {
										continue
									}
									m[8-v] = "0"
								}
								d.Write([]byte{gopsu.String2Int8(strings.Join(m, ""), 2),
									byte(pb2data.WlstTml.WlstSlu_6B00.CmdPwm.Scale),
									byte(pb2data.WlstTml.WlstSlu_6B00.CmdPwm.Rate / 100),
									0})
							}
							switch pb2data.WlstTml.WlstSlu_6B00.AddrType {
							case 0:
								d.WriteByte(0)
							case 1:
								d.WriteByte(gopsu.String2Int8(fmt.Sprintf("0001%04b", len(pb2data.WlstTml.WlstSlu_6B00.Addrs)), 2))
								for _, v := range pb2data.WlstTml.WlstSlu_6B00.Addrs {
									d.WriteByte(byte(v))
								}
							case 2:
								if pb2data.WlstTml.WlstSlu_6B00.Addrs[0] == 10 {
									d.WriteByte(0)
									d.WriteByte(0)
								} else {
									d.WriteByte(0xff)
									d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%02x", pb2data.WlstTml.WlstSlu_6B00.Addrs[0]), 16))
								}
							case 4:
								d.WriteByte(gopsu.String2Int8("00110000", 2))
								s := make([]string, 256)
								for i := 0; i < 256; i++ {
									s[i] = "0"
								}
								for _, v := range pb2data.WlstTml.WlstSlu_6B00.Addrs {
									s[256-v] = "1"
								}
								for i := 0; i < 256; i += 8 {
									d.WriteByte(gopsu.String2Int8(strings.Join(s[i:i+8], ""), 2))
								}
							}
						case "2400": // 启动/停止集中器巡测
							switch pb2data.WlstTml.WlstSlu_2400.DoFlag {
							case 0:
								d.WriteByte(0xa5)
							case 1:
								d.WriteByte(0x3c)
							case 2:
								d.WriteByte(0xaa)
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_2400.Status / 60))
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_2400.Status % 60))
							}
						case "2800": // 设置集中器停运/投运，允许/禁止主报
							var a, b string
							if pb2data.WlstTml.WlstSlu_2800.Status == 2 {
								a = "0101"
							} else {
								a = "1010"
							}
							if pb2data.WlstTml.WlstSlu_2800.Alarm == 2 {
								b = "0101"
							} else {
								b = "1010"
							}
							d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%s%s", b, a), 2))
						case "3000": // 设置集中器参数
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_3000.Ctrls % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_3000.Ctrls / 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_3000.DomainName % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_3000.DomainName / 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_3000.UpperVoltageLimit % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_3000.UpperVoltageLimit / 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_3000.LowerVoltageLimit % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_3000.LowerVoltageLimit / 256))
						case "1c00": // 设置控制器域名
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_1C00.CmdIdx))
							m := fmt.Sprintf("%08x", pb2data.WlstTml.WlstSlu_1C00.SluitemIdx)
							for i := 8; i > 0; i -= 2 {
								d.WriteByte(gopsu.String2Int8(m[i-2:i], 16))
							}
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_1C00.DomainName % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_1C00.DomainName / 256))
						case "1d00": // 选测未知控制器
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_1D00.CmdIdx))
							m := fmt.Sprintf("%08x", pb2data.WlstTml.WlstSlu_1D00.SluitemIdx)
							for i := 8; i > 0; i -= 2 {
								d.WriteByte(gopsu.String2Int8(m[i-2:i], 16))
							}
							m = fmt.Sprintf("%016b", pb2data.WlstTml.WlstSlu_1D00.DataMark)
							d.WriteByte(gopsu.String2Int8(m[8:], 2))
							d.WriteByte(gopsu.String2Int8(m[:8], 2))
						case "7000": // 复位以及参数初始化
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7000.CmdIdx))
							var s string
							if pb2data.WlstTml.WlstSlu_7000.ResetMark.ResetConcentrator == 1 {
								s = "1" + s
							} else {
								s = "0" + s
							}
							if pb2data.WlstTml.WlstSlu_7000.ResetMark.HardResetZigbee == 1 {
								s = "1" + s
							} else {
								s = "0" + s
							}
							if pb2data.WlstTml.WlstSlu_7000.ResetMark.SoftResetZigbee == 1 {
								s = "1" + s
							} else {
								s = "0" + s
							}
							if pb2data.WlstTml.WlstSlu_7000.ResetMark.ResetCarrier == 1 {
								s = "1" + s
							} else {
								s = "0" + s
							}
							if pb2data.WlstTml.WlstSlu_7000.ResetMark.InitAll == 1 {
								s = "1" + s
							} else {
								s = "0" + s
							}
							if pb2data.WlstTml.WlstSlu_7000.ResetMark.ClearData == 1 {
								s = "1" + s
							} else {
								s = "0" + s
							}
							if pb2data.WlstTml.WlstSlu_7000.ResetMark.ClearArgs == 1 {
								s = "1" + s
							} else {
								s = "0" + s
							}
							if pb2data.WlstTml.WlstSlu_7000.ResetMark.ClearTask == 1 {
								s = "1" + s
							} else {
								s = "0" + s
							}
							d.WriteByte(gopsu.String2Int8(s, 2))
						case "7100": // 时钟设置/读取(with udp)
							if pb2data.WlstTml.WlstSlu_7100.OptMark == 0 { // 对时
								// y, M, D, h, m, s, _ := gopsu.SplitDateTime(pb2data.WlstTml.WlstSlu_7100.DateTime)
								if scmd[1] == "slu" {
									// d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7100.CmdIdx))
									// d.WriteByte(1)
									// d.Write([]byte{y, M, D, h, m, s})
									d.Write(GetServerTimeMsg(0, 2, false, true))
								} else {
									cmd = fmt.Sprintf("wlst.%s.2100", scmd[1])
									// d.Write([]byte{2, 0, 0, 0, y, M, D, h, m, s})
									d.Write(GetServerTimeMsg(0, 3, false, true))
								}
							} else {
								if scmd[1] == "slu" {
									d.Write([]byte{byte(pb2data.WlstTml.WlstSlu_7100.CmdIdx), 0x81, 0, 0, 0, 0, 0, 0})
								} else {
									cmd = fmt.Sprintf("wlst.%s.2100", scmd[1])
									d.WriteByte(0)
									d.WriteByte(0)
									d.WriteByte(2)
									d.WriteByte(0)
								}
							}
						case "7200": // 控制器参数设置/读取(with udp)
							if scmd[1] == "slu" {
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7200.CmdIdx))
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7200.SluitemIdx % 256))
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7200.SluitemIdx / 256))
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7200.SluitemCount))
								m := fmt.Sprintf("%d000000%d%d%d%d%d%d%d%d%d",
									pb2data.WlstTml.WlstSlu_7200.DataMark.SetData,
									pb2data.WlstTml.WlstSlu_7200.DataMark.RatedPower,
									pb2data.WlstTml.WlstSlu_7200.DataMark.Vector,
									pb2data.WlstTml.WlstSlu_7200.DataMark.RunStatus,
									pb2data.WlstTml.WlstSlu_7200.DataMark.PowerOnStatus,
									pb2data.WlstTml.WlstSlu_7200.DataMark.Limit,
									pb2data.WlstTml.WlstSlu_7200.DataMark.Order,
									pb2data.WlstTml.WlstSlu_7200.DataMark.Route,
									pb2data.WlstTml.WlstSlu_7200.DataMark.Barcode,
									pb2data.WlstTml.WlstSlu_7200.DataMark.Group,
								)
								d.WriteByte(gopsu.String2Int8(m[8:], 2))
								d.WriteByte(gopsu.String2Int8(m[:8], 2))
								for i := int32(0); i < pb2data.WlstTml.WlstSlu_7200.SluitemCount; i++ {
									if pb2data.WlstTml.WlstSlu_7200.DataMark.SetData == 1 {
										if pb2data.WlstTml.WlstSlu_7200.DataMark.Group == 1 {
											for _, v := range pb2data.WlstTml.WlstSlu_7200.SluitemData[i].SluitemGroup {
												d.WriteByte(byte(v))
											}
										}
										if pb2data.WlstTml.WlstSlu_7200.DataMark.Barcode == 1 {
											m = fmt.Sprintf("%08x", pb2data.WlstTml.WlstSlu_7200.SluitemData[i].SluitemIdx)
											for x := len(m); x > 0; x = x - 2 {
												d.WriteByte(gopsu.String2Int8(m[x-2:x], 16))
											}
										}
										if pb2data.WlstTml.WlstSlu_7200.DataMark.Order == 1 {
											d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7200.SluitemData[i].SluitemOrder))
										}
										if pb2data.WlstTml.WlstSlu_7200.DataMark.Limit == 1 {
											d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7200.SluitemData[i].UpperPowerLimit))
											d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7200.SluitemData[i].LowerPowerLimit))
										}
										if pb2data.WlstTml.WlstSlu_7200.DataMark.PowerOnStatus == 1 {
											l := make([]string, 0)
											for _, v := range pb2data.WlstTml.WlstSlu_7200.SluitemData[i].SluitemPowerTurnon {
												if v == 1 {
													l = append(l, "0")
												} else {
													l = append(l, "1")
												}
											}
											l = append(l, "0", "0", "0", "0")
											ll := make([]string, 0)
											for i := len(l); i > 0; i-- {
												ll = append(ll, l[i-1])
											}
											d.WriteByte(gopsu.String2Int8(strings.Join(ll, ""), 2))
										}
										if pb2data.WlstTml.WlstSlu_7200.DataMark.RunStatus == 1 {
											var s string
											if pb2data.WlstTml.WlstSlu_7200.SluitemData[i].SluitemEnableAlarm == 1 {
												s = fmt.Sprintf("%04b", 5)
											} else {
												s = fmt.Sprintf("%04b", 0xa)
											}
											if pb2data.WlstTml.WlstSlu_7200.SluitemData[i].SluitemStatus == 1 {
												s += fmt.Sprintf("%04b", 5)
											} else {
												s += fmt.Sprintf("%04b", 0xa)
											}
											d.WriteByte(gopsu.String2Int8(s, 2))
										}
										if pb2data.WlstTml.WlstSlu_7200.DataMark.Vector == 1 {
											l := make([]string, 0)
											for _, v := range pb2data.WlstTml.WlstSlu_7200.SluitemData[i].SluitemVector {
												l = append(l, fmt.Sprintf("%02b", v-1))
											}
											ll := make([]string, 0)
											for i := len(l); i > 0; i-- {
												ll = append(ll, l[i-1])
											}
											d.WriteByte(gopsu.String2Int8(strings.Join(ll, ""), 2))
										}
										if pb2data.WlstTml.WlstSlu_7200.DataMark.RatedPower == 1 {
											l := make([]string, 0)
											for _, v := range pb2data.WlstTml.WlstSlu_7200.SluitemData[i].RatedPower {
												l = append(l, fmt.Sprintf("%04b", v))
											}
											ll := make([]string, 0)
											for i := len(l); i > 0; i-- {
												ll = append(ll, l[i-1])
											}
											mm := ll[2:]
											d.WriteByte(gopsu.String2Int8(strings.Join(mm, ""), 2))
											mm = ll[:2]
											d.WriteByte(gopsu.String2Int8(strings.Join(mm, ""), 2))
										}
									}
								}
							} else {
								cmd = fmt.Sprintf("wlst.%s.2100", scmd[1])
								if pb2data.WlstTml.WlstSlu_7200.DataMark.SetData == 1 {
									hasgroup, hasother := 0, 0
									if pb2data.WlstTml.WlstSlu_7200.DataMark.Group == 1 {
										hasgroup = 1
									}
									if pb2data.WlstTml.WlstSlu_7200.DataMark.RunStatus == 1 ||
										pb2data.WlstTml.WlstSlu_7200.DataMark.PowerOnStatus == 1 ||
										pb2data.WlstTml.WlstSlu_7200.DataMark.Vector == 1 {
										hasother = 1
									}
									d.Write([]byte{gopsu.String2Int8(fmt.Sprintf("000%d0%d00", hasgroup, hasother), 2), 0, 0, 0})
									lon := strings.Split(fmt.Sprintf("%.02f", pb2data.WlstTml.WlstSlu_7200.SluitemData[0].Longitude), ".")
									lat := strings.Split(fmt.Sprintf("%.02f", pb2data.WlstTml.WlstSlu_7200.SluitemData[0].Latitude), ".")

									d.Write([]byte{gopsu.String2Int8(lon[0], 10), gopsu.String2Int8(lon[1], 10), gopsu.String2Int8(lat[0], 10), gopsu.String2Int8(lat[1], 10), 1, 0})
									// d.Write([]byte{70, 0, 10, 0, 1, 0})
									if pb2data.WlstTml.WlstSlu_7200.DataMark.RunStatus == 1 {
										var s string
										if pb2data.WlstTml.WlstSlu_7200.SluitemData[0].SluitemEnableAlarm == 1 {
											s = fmt.Sprintf("%04b", 5)
										} else {
											s = fmt.Sprintf("%04b", 0xa)
										}
										if pb2data.WlstTml.WlstSlu_7200.SluitemData[0].SluitemStatus == 1 {
											s += fmt.Sprintf("%04b", 5)
										} else {
											s += fmt.Sprintf("%04b", 0xa)
										}
										d.WriteByte(gopsu.String2Int8(s, 2))
									} else {
										d.WriteByte(gopsu.String2Int8("01010101", 2))
									}
									if pb2data.WlstTml.WlstSlu_7200.DataMark.PowerOnStatus == 1 {
										l := make([]string, 0)
										for _, v := range pb2data.WlstTml.WlstSlu_7200.SluitemData[0].SluitemPowerTurnon {
											if v == 1 {
												l = append(l, "0")
											} else {
												l = append(l, "1")
											}
										}
										l = append(l, "0", "0", "0", "0")
										ll := make([]string, 0)
										for i := len(l); i > 0; i-- {
											ll = append(ll, l[i-1])
										}
										d.WriteByte(gopsu.String2Int8(strings.Join(ll, ""), 2))
									} else {
										d.WriteByte(0)
									}
									if pb2data.WlstTml.WlstSlu_7200.DataMark.Vector == 1 {
										l := make([]string, 0)
										for _, v := range pb2data.WlstTml.WlstSlu_7200.SluitemData[0].SluitemVector {
											l = append(l, fmt.Sprintf("%02b", v-1))
										}
										ll := make([]string, 0)
										for i := len(l); i > 0; i-- {
											ll = append(ll, l[i-1])
										}
										d.WriteByte(gopsu.String2Int8(strings.Join(ll, ""), 2))
									} else {
										d.WriteByte(gopsu.String2Int8("11100100", 2))
									}
									if pb2data.WlstTml.WlstSlu_7200.DataMark.RatedPower == 1 {
										l := make([]string, 0)
										for _, v := range pb2data.WlstTml.WlstSlu_7200.SluitemData[0].RatedPower {
											l = append(l, fmt.Sprintf("%04b", v))
										}
										ll := make([]string, 0)
										for i := len(l); i > 0; i-- {
											ll = append(ll, l[i-1])
										}
										mm := ll[2:]
										d.WriteByte(gopsu.String2Int8(strings.Join(mm, ""), 2))
										mm = ll[:2]
										d.WriteByte(gopsu.String2Int8(strings.Join(mm, ""), 2))
									} else {
										d.WriteByte(0)
										d.WriteByte(0)
									}
									//NB主报参数
									//if pb2data.WlstTml.WlstSlu_7200.SluitemData[0].UplinkReply != 0 && pb2data.WlstTml.WlstSlu_7200.SluitemData[0].UplinkTimer != 0 {
									zb := fmt.Sprintf("%b%07b", pb2data.WlstTml.WlstSlu_7200.SluitemData[0].UplinkReply, pb2data.WlstTml.WlstSlu_7200.SluitemData[0].UplinkTimer/5)
									d.WriteByte(gopsu.String2Int8(zb, 2))
									// } else {
									// 	d.WriteByte(0)
									// }
								} else {
									hasgroup, hasother := 0, 0
									if pb2data.WlstTml.WlstSlu_7200.DataMark.Group == 1 {
										hasgroup = 1
									}
									if pb2data.WlstTml.WlstSlu_7200.DataMark.RunStatus == 1 ||
										pb2data.WlstTml.WlstSlu_7200.DataMark.PowerOnStatus == 1 ||
										pb2data.WlstTml.WlstSlu_7200.DataMark.Vector == 1 {
										hasother = 1
									}
									d.WriteByte(0)
									d.WriteByte(0)
									d.WriteByte(gopsu.String2Int8(fmt.Sprintf("000%d0%d00", hasgroup, hasother), 2))
									d.WriteByte(0)
								}
							}
						case "7300": // 选测(with udp)
							if scmd[1] == "slu" {
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7300.CmdIdx))
								mark := gopsu.String2Int32(fmt.Sprintf("%04b%012b",
									pb2data.WlstTml.WlstSlu_7300.DataMark,
									pb2data.WlstTml.WlstSlu_7300.SluitemStart), 2)
								d.WriteByte(byte(mark % 256))
								d.WriteByte(byte(mark / 256))
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7300.SluitemCount))
							} else {
								cmd = fmt.Sprintf("wlst.%s.2100", scmd[1])
								switch pb2data.WlstTml.WlstSlu_7300.DataMark {
								case 4:
									d.WriteByte(0)
									d.WriteByte(0)
									d.WriteByte(0x20)
									d.WriteByte(0)
								case 7:
									d.WriteByte(0)
									d.WriteByte(0)
									d.WriteByte(0)
									d.WriteByte(0x4)
								default:
									d.WriteByte(0)
									d.WriteByte(0)
									d.WriteByte(0)
									d.WriteByte(0)
								}
							}
						case "7400": // 设置短程控制参数，485(with udp)
							if scmd[1] == "slu" {
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7400.CmdIdx))
								m := fmt.Sprintf("%04b%04b", pb2data.WlstTml.WlstSlu_7400.OperationOrder, pb2data.WlstTml.WlstSlu_7400.OperationType)
								d.WriteByte(gopsu.String2Int8(m, 2))
								switch pb2data.WlstTml.WlstSlu_7400.OperationType {
								case 0, 3:
									d.WriteByte(0)
									d.WriteByte(0)
									d.WriteByte(0)
								case 1, 2:
									m = ""
									for _, v := range pb2data.WlstTml.WlstSlu_7400.WeekSet {
										m = strconv.FormatInt(int64(v), 10) + m
									}
									d.WriteByte(gopsu.String2Int8(m, 2))
									switch pb2data.WlstTml.WlstSlu_7400.OperationType {
									case 1:
										d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7400.TimerOrOffset / 60))
										d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7400.TimerOrOffset % 60))
									case 2:
										if pb2data.WlstTml.WlstSlu_7400.TimerOrOffset < 0 {
											m = fmt.Sprintf("1%015b", 0-pb2data.WlstTml.WlstSlu_7400.TimerOrOffset)
										} else {
											m = fmt.Sprintf("0%015b", pb2data.WlstTml.WlstSlu_7400.TimerOrOffset)
										}
										d.WriteByte(gopsu.String2Int8(m[8:], 2))
										d.WriteByte(gopsu.String2Int8(m[:8], 2))
									}
								}
								switch pb2data.WlstTml.WlstSlu_7400.AddrType {
								case 0:
									d.WriteByte(0)
									d.WriteByte(0)
								case 1:
									d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7400.Addrs[0]))
									d.WriteByte(0xff)
								case 2:
									if pb2data.WlstTml.WlstSlu_7400.Addrs[0] == 10 {
										d.WriteByte(0)
										d.WriteByte(0)
									} else {
										x, _ := strconv.ParseInt(strconv.FormatInt(int64(pb2data.WlstTml.WlstSlu_7400.Addrs[0]), 10), 16, 0)
										d.WriteByte(0xff)
										d.WriteByte(byte(x))
									}
								case 3:
									d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7400.Addrs[0] % 256))
									d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7400.Addrs[0] / 256))
								case 4:
									cmd = "wlst.slu.7d00"
									sad := make([]string, 256)
									for i := 0; i < 256; i++ {
										sad[i] = "0"
									}
									for _, v := range pb2data.WlstTml.WlstSlu_7400.Addrs {
										sad[v-1] = "1"
									}
									sadd := gopsu.ReverseString(strings.Join(sad, ""))
									for i := 255; i > 0; i -= 8 {
										d.WriteByte(gopsu.String2Int8(sadd[i-8:i], 2))
									}
								}
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7400.CmdType))
								switch pb2data.WlstTml.WlstSlu_7400.CmdType {
								case 3:
									for _, v := range pb2data.WlstTml.WlstSlu_7400.CmdMix {
										if v < 4 {
											d.WriteByte(1)
										} else {
											d.WriteByte(0)
										}
									}
								case 4:
									if len(pb2data.WlstTml.WlstSlu_7400.CmdMix) == 0 {
										d.WriteByte(0)
										d.WriteByte(0)
										d.WriteByte(0)
										d.WriteByte(0)
									} else {
										for k, v := range pb2data.WlstTml.WlstSlu_7400.CmdMix {
											if k > 3 {
												break
											}
											switch v {
											case 0:
												d.WriteByte(0)
											case 1:
												d.WriteByte(0x33)
											case 2:
												d.WriteByte(0x55)
											case 3:
												d.WriteByte(0xaa)
											case 4:
												d.WriteByte(0xcc)
											}
										}
									}
								case 5:
									mm := []string{"1", "1", "1", "1", "1", "1", "1", "1"}
									for _, v := range pb2data.WlstTml.WlstSlu_7400.CmdPwm.LoopCanDo {
										if v > 8 || v < 1 {
											// mm[8-v] = "1"
										} else {
											mm[8-v] = "0"
										}
									}
									d.WriteByte(gopsu.String2Int8(strings.Join(mm, ""), 2))
									if pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale < 10 {
										pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale = pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale * 10
									}
									d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale))
									d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7400.CmdPwm.Rate / 100))
									d.WriteByte(0)
								}
							} else {
								cmd = fmt.Sprintf("wlst.%s.2100", scmd[1])
								d.Write([]byte{0, 2, 0, 0, 1, 0, 0, 0, 0}) // 设置本地控制参数（新）
								if pb2data.WlstTml.WlstSlu_7400.CmdType > 3 {
									d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04b%04b", pb2data.WlstTml.WlstSlu_7400.OperationType, pb2data.WlstTml.WlstSlu_7400.CmdType-4), 2))
								} else {
									d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04b%04b", pb2data.WlstTml.WlstSlu_7400.OperationType, 0), 2))
								}
								d.WriteByte(0)
								d.WriteByte(0)
								d.WriteByte(0)
								switch pb2data.WlstTml.WlstSlu_7400.CmdType {
								case 4:
									if len(pb2data.WlstTml.WlstSlu_7400.CmdMix) == 0 {
										d.WriteByte(0)
										d.WriteByte(0)
									} else {
										m1 := "0000"
										m2 := "0000"
										for k, v := range pb2data.WlstTml.WlstSlu_7400.CmdMix {
											if k > 3 {
												break
											}
											switch k {
											case 0:
												switch v {
												case 0:
													m1 = fmt.Sprintf("%04b", 0)
												case 1:
													m1 = fmt.Sprintf("%04b", 0x3)
												case 2:
													m1 = fmt.Sprintf("%04b", 0x5)
												case 3:
													m1 = fmt.Sprintf("%04b", 0xa)
												case 4:
													m1 = fmt.Sprintf("%04b", 0xc)
												}
											case 1:
												switch v {
												case 0:
													m1 = fmt.Sprintf("%04b", 0) + m1
												case 1:
													m1 = fmt.Sprintf("%04b", 0x3) + m1
												case 2:
													m1 = fmt.Sprintf("%04b", 0x5) + m1
												case 3:
													m1 = fmt.Sprintf("%04b", 0xa) + m1
												case 4:
													m1 = fmt.Sprintf("%04b", 0xc) + m1
												}
											case 2:
												switch v {
												case 0:
													m2 = fmt.Sprintf("%04b", 0)
												case 1:
													m2 = fmt.Sprintf("%04b", 0x3)
												case 2:
													m2 = fmt.Sprintf("%04b", 0x5)
												case 3:
													m2 = fmt.Sprintf("%04b", 0xa)
												case 4:
													m2 = fmt.Sprintf("%04b", 0xc)
												}
											case 3:
												switch v {
												case 0:
													m2 = fmt.Sprintf("%04b", 0) + m2
												case 1:
													m2 = fmt.Sprintf("%04b", 0x3) + m2
												case 2:
													m2 = fmt.Sprintf("%04b", 0x5) + m2
												case 3:
													m2 = fmt.Sprintf("%04b", 0xa) + m2
												case 4:
													m2 = fmt.Sprintf("%04b", 0xc) + m2
												}
											}
										}
										d.WriteByte(gopsu.String2Int8(m1, 2))
										d.WriteByte(gopsu.String2Int8(m2, 2))
									}
								case 5:
									m := []string{"0", "0", "0", "0"}
									for _, v := range pb2data.WlstTml.WlstSlu_7400.CmdPwm.LoopCanDo {
										m[v-1] = "1"
									}
									var m1, m2 string
									if pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale < 10 {
										pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale = pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale * 10
									}
									m1 = fmt.Sprintf("%04b", pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale/10) + gopsu.ReverseString(strings.Join(m, ""))
									m2 = fmt.Sprintf("%04b%04b", pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale%10, pb2data.WlstTml.WlstSlu_7400.CmdPwm.Rate/100)
									d.WriteByte(gopsu.String2Int8(m1, 2))
									d.WriteByte(gopsu.String2Int8(m2, 2))
								}
								// d.Write([]byte{0, 4, 0, 0, 1}) // 即时控制
								// d.Write(make([]byte, 31))
								// // for i := 0; i < 31; i++ {
								// // 	d.WriteByte(0)
								// // }
								// // d.WriteByte(1)
								// // d.WriteByte(0)
								// // d.WriteByte(0)
								// // d.WriteByte(0)
								// // d.WriteByte(0)
								// if pb2data.WlstTml.WlstSlu_7400.CmdType > 3 {
								// 	d.WriteByte(mxgo.String2Int8(fmt.Sprintf("%04b%04b", pb2data.WlstTml.WlstSlu_7400.OperationType, pb2data.WlstTml.WlstSlu_7400.CmdType-4), 2))
								// } else {
								// 	d.WriteByte(mxgo.String2Int8(fmt.Sprintf("%04b%04b", pb2data.WlstTml.WlstSlu_7400.OperationType, 0), 2))
								// }
								// // switch pb2data.WlstTml.WlstSlu_7400.OperationType {
								// // case 0, 3:
								// // 	d.WriteByte(0)
								// // 	d.WriteByte(0)
								// // 	d.WriteByte(0)
								// // case 1, 2:
								// // 	m := ""
								// // 	for _, v := range pb2data.WlstTml.WlstSlu_7400.WeekSet {
								// // 		m = strconv.FormatInt(int64(v), 10) + m
								// // 	}
								// // 	d.WriteByte(mxgo.String2Int8(m, 2))
								// // 	switch pb2data.WlstTml.WlstSlu_7400.OperationType {
								// // 	case 1:
								// // 		d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7400.TimerOrOffset / 60))
								// // 		d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7400.TimerOrOffset % 60))
								// // 	case 2:
								// // 		if pb2data.WlstTml.WlstSlu_7400.TimerOrOffset < 0 {
								// // 			m = fmt.Sprintf("1%015b", 0-pb2data.WlstTml.WlstSlu_7400.TimerOrOffset)
								// // 		} else {
								// // 			m = fmt.Sprintf("0%015b", pb2data.WlstTml.WlstSlu_7400.TimerOrOffset)
								// // 		}
								// // 		d.WriteByte(mxgo.String2Int8(m[8:], 2))
								// // 		d.WriteByte(mxgo.String2Int8(m[:8], 2))
								// // 	}
								// // }
								// switch pb2data.WlstTml.WlstSlu_7400.CmdType {
								// case 4:
								// 	if len(pb2data.WlstTml.WlstSlu_7400.CmdMix) == 0 {
								// 		d.WriteByte(0)
								// 		d.WriteByte(0)
								// 	} else {
								// 		m1 := "0000"
								// 		m2 := "0000"
								// 		for k, v := range pb2data.WlstTml.WlstSlu_7400.CmdMix {
								// 			if k > 3 {
								// 				break
								// 			}
								// 			switch k {
								// 			case 0:
								// 				switch v {
								// 				case 0:
								// 					m1 = fmt.Sprintf("%04b", 0)
								// 				case 1:
								// 					m1 = fmt.Sprintf("%04b", 0x3)
								// 				case 2:
								// 					m1 = fmt.Sprintf("%04b", 0x5)
								// 				case 3:
								// 					m1 = fmt.Sprintf("%04b", 0xa)
								// 				case 4:
								// 					m1 = fmt.Sprintf("%04b", 0xc)
								// 				}
								// 			case 1:
								// 				switch v {
								// 				case 0:
								// 					m1 = fmt.Sprintf("%04b", 0) + m1
								// 				case 1:
								// 					m1 = fmt.Sprintf("%04b", 0x3) + m1
								// 				case 2:
								// 					m1 = fmt.Sprintf("%04b", 0x5) + m1
								// 				case 3:
								// 					m1 = fmt.Sprintf("%04b", 0xa) + m1
								// 				case 4:
								// 					m1 = fmt.Sprintf("%04b", 0xc) + m1
								// 				}
								// 			case 2:
								// 				switch v {
								// 				case 0:
								// 					m2 = fmt.Sprintf("%04b", 0)
								// 				case 1:
								// 					m2 = fmt.Sprintf("%04b", 0x3)
								// 				case 2:
								// 					m2 = fmt.Sprintf("%04b", 0x5)
								// 				case 3:
								// 					m2 = fmt.Sprintf("%04b", 0xa)
								// 				case 4:
								// 					m2 = fmt.Sprintf("%04b", 0xc)
								// 				}
								// 			case 3:
								// 				switch v {
								// 				case 0:
								// 					m2 = fmt.Sprintf("%04b", 0) + m2
								// 				case 1:
								// 					m2 = fmt.Sprintf("%04b", 0x3) + m2
								// 				case 2:
								// 					m2 = fmt.Sprintf("%04b", 0x5) + m2
								// 				case 3:
								// 					m2 = fmt.Sprintf("%04b", 0xa) + m2
								// 				case 4:
								// 					m2 = fmt.Sprintf("%04b", 0xc) + m2
								// 				}
								// 			}
								// 		}
								// 		d.WriteByte(mxgo.String2Int8(m1, 2))
								// 		d.WriteByte(mxgo.String2Int8(m2, 2))
								// 	}
								// case 5:
								// 	m := []string{"0", "0", "0", "0"}
								// 	for _, v := range pb2data.WlstTml.WlstSlu_7400.CmdPwm.LoopCanDo {
								// 		m[v-1] = "1"
								// 	}
								// 	var m1, m2 string
								// 	if pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale < 10 {
								// 		pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale = pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale * 10
								// 	}
								// 	m1 = fmt.Sprintf("%04b", pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale/10) + mxgo.ReverseString(strings.Join(m, ""))
								// 	m2 = fmt.Sprintf("%04b%04b", pb2data.WlstTml.WlstSlu_7400.CmdPwm.Scale%10, pb2data.WlstTml.WlstSlu_7400.CmdPwm.Rate/100)
								// 	d.WriteByte(mxgo.String2Int8(m1, 2))
								// 	d.WriteByte(mxgo.String2Int8(m2, 2))
								// }
							}
						case "7c00": // 设置本地控制参数（新）(with udp)
							if scmd[1] == "slu" {
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7C00.CmdIdx))
								switch pb2data.WlstTml.WlstSlu_7C00.AddrType {
								case 0:
									d.WriteByte(0)
									d.WriteByte(0)
								case 1:
									d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7C00.Addr))
									d.WriteByte(0xff)
								case 2:
									if pb2data.WlstTml.WlstSlu_7C00.Addr == 10 {
										d.WriteByte(0)
										d.WriteByte(0)
									} else {
										d.WriteByte(0xff)
										d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7C00.Addr))
									}
								case 3:
									d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7C00.Addr % 256))
									d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7C00.Addr / 256))
								}
							} else {
								cmd = fmt.Sprintf("wlst.%s.2100", scmd[1])
								d.WriteByte(0)
								d.WriteByte(2)
								d.WriteByte(0)
								d.WriteByte(0)
							}
							m := fmt.Sprintf("%d%07b", pb2data.WlstTml.WlstSlu_7C00.AddOrUpdate, pb2data.WlstTml.WlstSlu_7C00.CmdCount)
							d.WriteByte(gopsu.String2Int8(m, 2))
							d.Write([]byte{0, 0, 0, 0})
							for i := int32(0); i < pb2data.WlstTml.WlstSlu_7C00.CmdCount; i++ {
								m := fmt.Sprintf("%04b%04b", pb2data.WlstTml.WlstSlu_7C00.OperationData[i].OperationType,
									pb2data.WlstTml.WlstSlu_7C00.OperationData[i].CmdType-4)
								d.WriteByte(gopsu.String2Int8(m, 2))

								switch pb2data.WlstTml.WlstSlu_7C00.OperationData[i].OperationType {
								case 1:
									m = ""
									for _, v := range pb2data.WlstTml.WlstSlu_7C00.OperationData[i].WeekSet {
										m += strconv.FormatInt(int64(v), 10)
									}
									m = gopsu.ReverseString(m)
									d.WriteByte(gopsu.String2Int8(m, 2))
									d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7C00.OperationData[i].TimerOrOffset / 60))
									d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7C00.OperationData[i].TimerOrOffset % 60))
								case 2:
									m = ""
									for _, v := range pb2data.WlstTml.WlstSlu_7C00.OperationData[i].WeekSet {
										m += strconv.FormatInt(int64(v), 10)
									}
									m = gopsu.ReverseString(m)
									d.WriteByte(gopsu.String2Int8(m, 2))
									if pb2data.WlstTml.WlstSlu_7C00.OperationData[i].TimerOrOffset < 0 {
										m = fmt.Sprintf("1%015b", 0-pb2data.WlstTml.WlstSlu_7C00.OperationData[i].TimerOrOffset)
									} else {
										m = fmt.Sprintf("0%015b", pb2data.WlstTml.WlstSlu_7C00.OperationData[i].TimerOrOffset)
									}
									d.WriteByte(gopsu.String2Int8(m[8:], 2))
									d.WriteByte(gopsu.String2Int8(m[:8], 2))
								case 3:
									d.WriteByte(0)
									d.WriteByte(0)
									d.WriteByte(0)
								}
								switch pb2data.WlstTml.WlstSlu_7C00.OperationData[i].CmdType {
								case 4:
									m = ""
									for j := 0; j < 4; j++ {
										switch pb2data.WlstTml.WlstSlu_7C00.OperationData[i].CmdMix[j] {
										case 0:
											m = fmt.Sprintf("%04b", 0) + m
										case 1:
											m = fmt.Sprintf("%04b", 3) + m
										case 2:
											m = fmt.Sprintf("%04b", 5) + m
										case 3:
											m = fmt.Sprintf("%04b", 0x0a) + m
										case 4:
											m = fmt.Sprintf("%04b", 0x0c) + m
										}
									}
									d.WriteByte(gopsu.String2Int8(m[8:], 2))
									d.WriteByte(gopsu.String2Int8(m[:8], 2))
								case 5:
									n := []string{"0", "0", "0", "0"}
									for _, v := range pb2data.WlstTml.WlstSlu_7C00.OperationData[i].CmdPwm.LoopCanDo {
										n[v-1] = "1"
									}
									m = gopsu.ReverseString(strings.Join(n, ""))
									if pb2data.WlstTml.WlstSlu_7C00.OperationData[i].CmdPwm.Scale < 10 {
										pb2data.WlstTml.WlstSlu_7C00.OperationData[i].CmdPwm.Scale = pb2data.WlstTml.WlstSlu_7C00.OperationData[i].CmdPwm.Scale * 10
									}
									d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04b%s", pb2data.WlstTml.WlstSlu_7C00.OperationData[i].CmdPwm.Scale/10, m), 2))
									d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04b%04b", pb2data.WlstTml.WlstSlu_7C00.OperationData[i].CmdPwm.Scale%10, pb2data.WlstTml.WlstSlu_7C00.OperationData[i].CmdPwm.Rate/100), 2))
								}
							}
						case "7600": // 设置集中器报警参数
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7600.CmdIdx))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7600.CommunicationFailures))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7600.PowerFactor))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7600.CommunicationChannel % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7600.CommunicationChannel / 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7600.CurrentRange * 10))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7600.PowerRange / 10))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7600.AutoMode))
							// s := strconv.FormatFloat(pb2data.WlstTml.WlstSlu_7600.Longitude, 'f', 2, 64)
							s := fmt.Sprintf("%.02f", pb2data.WlstTml.WlstSlu_7600.Longitude)
							d.WriteByte(gopsu.String2Int8(strings.Split(s, ".")[0], 10))
							d.WriteByte(gopsu.String2Int8(strings.Split(s, ".")[1], 10))
							s = fmt.Sprintf("%.02f", pb2data.WlstTml.WlstSlu_7600.Latitude)
							// s = strconv.FormatFloat(pb2data.WlstTml.WlstSlu_7600.Latitude, 'f', 2, 64)
							d.WriteByte(gopsu.String2Int8(strings.Split(s, ".")[0], 10))
							d.WriteByte(gopsu.String2Int8(strings.Split(s, ".")[1], 10))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7600.CarrierRoutingMode))
							s = fmt.Sprintf("%08x", pb2data.WlstTml.WlstSlu_7600.BluetoothPin)
							for i := 8; i > 0; i -= 2 {
								d.WriteByte(gopsu.String2Int8(s[i-2:i], 16))
							}
							// 蓝牙模式默认1
							d.WriteByte(1)
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7600.Cct))
							d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7600.AlwaysOnline))
							// 保留字节
							d.WriteByte(0)
							d.WriteByte(0)
						case "7a00": // 选测控制器参数(with udp)
							if scmd[1] == "slu" {
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7A00.CmdIdx))
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7A00.SluitemIdx % 256))
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7A00.SluitemIdx / 256))
								m := fmt.Sprintf("00000%d%d00%d%d%d0%d%d%d",
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadCtrldata,
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadTimetable,
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadSunriseset,
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadVer,
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadGroup,
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadArgs,
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadTimer,
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadData)
								d.WriteByte(gopsu.String2Int8(m[8:], 2))
								d.WriteByte(gopsu.String2Int8(m[:8], 2))
							} else {
								cmd = fmt.Sprintf("wlst.%s.2100", scmd[1])
								d.WriteByte(0)
								d.WriteByte(0)
								m := fmt.Sprintf("00000%d%d000%d%d0%d%d0",
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadCtrldata,
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadTimetable,
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadVer,
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadGroup,
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadArgs,
									pb2data.WlstTml.WlstSlu_7A00.DataMark.ReadTimer)
								d.WriteByte(gopsu.String2Int8(m[8:], 2))
								d.WriteByte(gopsu.String2Int8(m[:8], 2))
							}
						case "7b00": // 读取短程控制参数(with udp)
							if scmd[1] == "slu" {
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7B00.CmdIdx))
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7B00.SluitemIdx))
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_7B00.DataCount))
							} else {
								cmd = fmt.Sprintf("wlst.%s.2100", scmd[1])
								d.WriteByte(0)
								d.WriteByte(0)
								d.WriteByte(0)
								d.WriteByte(2)
							}
						case "6f00": // 控制器复位以及初始化(with udp)
							if scmd[1] == "slu" {
								d.WriteByte(byte(pb2data.WlstTml.WlstSlu_6F00.CmdIdx))
								switch pb2data.WlstTml.WlstSlu_6F00.AddrType {
								case 0:
									d.WriteByte(0)
									d.WriteByte(0)
								case 1:
									d.WriteByte(byte(pb2data.WlstTml.WlstSlu_6F00.Addr))
									d.WriteByte(0xff)
								case 2:
									if pb2data.WlstTml.WlstSlu_6F00.Addr == 10 {
										d.WriteByte(0)
										d.WriteByte(0)
									} else {
										d.WriteByte(0xff)
										d.WriteByte(gopsu.String2Int8(strconv.FormatInt(int64(pb2data.WlstTml.WlstSlu_6F00.Addr), 10), 16))
									}
								case 3:
									d.WriteByte(byte(pb2data.WlstTml.WlstSlu_6F00.Addr % 256))
									d.WriteByte(byte(pb2data.WlstTml.WlstSlu_6F00.Addr / 256))
								}
								m := fmt.Sprintf("00%d%d%d%d%d%d",
									pb2data.WlstTml.WlstSlu_6F00.ResetMark.ZeroCount,
									pb2data.WlstTml.WlstSlu_6F00.ResetMark.ZeroEerom,
									pb2data.WlstTml.WlstSlu_6F00.ResetMark.InitRam,
									pb2data.WlstTml.WlstSlu_6F00.ResetMark.InitMcuHardware,
									pb2data.WlstTml.WlstSlu_6F00.ResetMark.ResetComm,
									pb2data.WlstTml.WlstSlu_6F00.ResetMark.ResetMcu)
								d.WriteByte(gopsu.String2Int8(m, 2))
							} else {
								cmd = fmt.Sprintf("wlst.%s.2100", scmd[1])
								d.WriteByte(0x20)
								d.WriteByte(0)
								d.WriteByte(0)
								d.WriteByte(0)
								d.WriteByte(0x3f)
							}
						case "5000": // 读取版本(with udp)
							if scmd[1] == "vslu" {
								cmd = fmt.Sprintf("wlst.%s.2100", scmd[1])
								d.WriteByte(0)
								d.WriteByte(0)
								d.WriteByte(0x10)
								d.WriteByte(0)
							}
						case "3200", "1a00", "4d00":
						default:
							getprotocol = false
						}
					case "ldu": // 防盗
						br = 2
						rc = 5
						switch scmd[2] {
						case "7800": // 招测事件记录
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7800.EventType))
							y, m, dd, h, mm, _, _ := gopsu.SplitDateTime(pb2data.WlstTml.WlstRtu_7800.DtStart)
							d.WriteByte(y)
							d.WriteByte(m)
							d.WriteByte(dd)
							d.WriteByte(h)
							d.WriteByte(mm)
							y, m, dd, h, mm, _, _ = gopsu.SplitDateTime(pb2data.WlstTml.WlstRtu_7800.DtEnd)
							d.WriteByte(y)
							d.WriteByte(m)
							d.WriteByte(dd)
							d.WriteByte(h)
							d.WriteByte(mm)
						case "4900": // 设置检测参数
							d.WriteByte(byte(pb2data.WlstTml.WlstLdu_4900.LoopMark))
							for _, v := range pb2data.WlstTml.WlstLdu_4900.LduLoopArgv {
								d.WriteByte(byte(v.XDetectionFlag))
								d.WriteByte(byte(v.XTransformer / 5))
								d.WriteByte(byte(v.XPhase))
								d.WriteByte(byte(v.XOnSignalStrength / 10))
								d.WriteByte(byte(v.XOnImpedanceAlarm / 10))
								d.WriteByte(byte(v.XLightingRate))
								d.WriteByte(byte(v.XOffSignalStrength / 10))
								d.WriteByte(byte(v.XOffImpedanceAlarm / 10))
								d.WriteByte(0)
								d.WriteByte(0)
							}
						case "2600": // 选测
							d.WriteByte(byte(pb2data.WlstTml.WlstLdu_2600.LoopMark))
						case "5b00": // 读取检测参数
							d.WriteByte(byte(pb2data.WlstTml.WlstLdu_5B00.LoopMark))
						case "4a01": // 自适应门限设置/选测开灯阻抗基准/选测开灯阻抗最大值/复位开灯阻抗
							d.WriteByte(0x01)
							d.WriteByte(byte(pb2data.WlstTml.WlstLdu_4A01.LoopMark))
						case "4d01":
							d.WriteByte(0x01)
							d.WriteByte(byte(pb2data.WlstTml.WlstLdu_4D01.LoopMark))
						case "4d02":
							d.WriteByte(0x02)
							d.WriteByte(byte(pb2data.WlstTml.WlstLdu_4D02.LoopMark))
						case "4d03":
							d.WriteByte(0x03)
							d.WriteByte(byte(pb2data.WlstTml.WlstLdu_4D03.LoopMark))
						case "5c00":
						default:
							getprotocol = false
						}
					case "als": // 光照度
						br = 5
						rc = 0
						switch scmd[2] {
						case "2500":
							d.WriteByte(0)
							d.WriteByte(byte(pb2data.WlstTml.WlstAls_2500.Addr))
						case "2700":
							d.WriteByte(0)
							d.WriteByte(byte(pb2data.WlstTml.WlstAls_2700.Addr))
						case "4700":
							d.WriteByte(0)
							d.WriteByte(byte(pb2data.WlstTml.WlstAls_4700.Addr))
						case "4800":
							d.WriteByte(0)
							d.WriteByte(byte(pb2data.WlstTml.WlstAls_4800.Addr))
						case "4a00":
							d.WriteByte(0)
							d.WriteByte(byte(pb2data.WlstTml.WlstAls_4A00.Addr))
						case "3600":
							d.WriteByte(byte(pb2data.WlstTml.WlstAls_3600.Mode))
						case "3700":
							d.WriteByte(0)
							d.WriteByte(byte(pb2data.WlstTml.WlstAls_3700.Addr))
							d.WriteByte(byte(pb2data.WlstTml.WlstAls_3700.Mode))
						case "3800":
							d.WriteByte(0)
							d.WriteByte(byte(pb2data.WlstTml.WlstAls_3800.Addr))
							d.WriteByte(byte(pb2data.WlstTml.WlstAls_3800.Time % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstAls_3800.Time / 256))
						case "2600", "4600":
						default:
							getprotocol = false
						}
					case "esu": // 节能
						br = 5
						rc = 0
						switch scmd[2] {
						case "1000": // 复位mcu
							d.WriteByte(0)
						case "1100": // 设置工作参数
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1100.WarmupTime))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1100.OnTime / 60))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1100.OnTime % 60))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1100.OffTime / 60))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1100.OffTime % 60))
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(0)
						case "1400": // 发送定时调压参数
							for k, v := range pb2data.WlstTml.WlstEsu_1400.XAdjustTime {
								d.WriteByte(byte(v / 60))
								d.WriteByte(byte(v % 60))
								d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1400.XAdjustValue[k] * 100 % 256))
								d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1400.XAdjustValue[k] * 100 / 256))
							}
						case "1600": // 对时
							d.Write(GetServerTimeMsg(0, 4, false, true))
							// y, m, dd, h, mm, s, _ := gopsu.SplitDateTime(0)
							// d.WriteByte(y)
							// d.WriteByte(m)
							// d.WriteByte(dd)
							// d.WriteByte(h)
							// d.WriteByte(mm)
							// d.WriteByte(s)
						case "1700":
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1700.No))
						case "1800": // 手动调压
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1800.AdjustValue * 100 % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1800.AdjustValue * 100 / 256))
						case "1900":
							if pb2data.WlstTml.WlstEsu_1900.ManualControl == 1 {
								d.WriteByte(0x55)
							} else {
								d.WriteByte(0xaa)
							}
						case "2500": // 停运/投运
							if pb2data.WlstTml.WlstEsu_2500.ManualControl == 1 {
								d.WriteByte(0x55)
							} else {
								d.WriteByte(0xaa)
							}
						case "1d00":
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.WarmupTime))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.OnTime / 60))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.OnTime % 60))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.OffTime / 60))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.OffTime % 60))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.TransformerA / 5))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.TransformerB / 5))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.TransformerC / 5))
							if pb2data.WlstTml.WlstEsu_1D00.TimeMode == 1 {
								d.WriteByte(0x55)
							} else {
								d.WriteByte(0xaa)
							}
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.RunMode))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.FanStartTemperature))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.FanStopTemperature))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.SaverStopTemperature))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.ProtectionTemperature))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.SaverRecoverTemperature))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.InputOvervoltage * 100 % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.InputOvervoltage * 100 / 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.InputUndervoltage * 100 % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.InputUndervoltage * 100 / 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.OutputOverload * 100 % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.OutputOverload * 100 / 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.OutputUndervoltage * 100 % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.OutputUndervoltage * 100 / 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.AdjustSpeed))
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.PhaseCount))
							if pb2data.WlstTml.WlstEsu_1D00.CommunicateMode == 1 {
								d.WriteByte(0x55)
							} else {
								d.WriteByte(0xaa)
							}
							if pb2data.WlstTml.WlstEsu_1D00.WorkMode == 1 {
								d.WriteByte(0x55)
							} else {
								d.WriteByte(0xaa)
							}
							if pb2data.WlstTml.WlstEsu_1D00.AlarmOn == 1 {
								d.WriteByte(0x55)
							} else {
								d.WriteByte(0xaa)
							}
							d.WriteByte(byte(pb2data.WlstTml.WlstEsu_1D00.AlarmDelay))
							if pb2data.WlstTml.WlstEsu_1D00.SaverMode == 1 {
								d.WriteByte(0x55)
							} else {
								d.WriteByte(0xaa)
							}
						case "1f00", "1f01", "1f02", "1f03":
							d.WriteByte(gopsu.String2Int8(scmd[2][2:], 16))
						case "2300":
						case "1a00":
						case "1200", "1300", "1500", "1b00", "1e00":
						default:
							getprotocol = false
						}
					case "mru": // 抄表
						rc = 0x55
						switch scmd[2] {
						case "1100": // 读数据
							br = byte(pb2data.WlstTml.WlstMru_1100.BaudRate)
							for _, v := range pb2data.WlstTml.WlstMru_1100.Addr {
								d.WriteByte(byte(v))
							}
							if pb2data.WlstTml.WlstMru_1100.Ver == 2 { // 2007
								d.WriteByte(0x11)
								d.WriteByte(0x4)
								switch pb2data.WlstTml.WlstMru_1100.MeterReadingType {
								case 1:
									d.WriteByte(byte(pb2data.WlstTml.WlstMru_1100.MeterReadingDate + 0x33))
									d.WriteByte(0x00 + 0x33)
									d.WriteByte(0x15 + 0x33)
									d.WriteByte(0x00 + 0x33)
								case 2:
									d.WriteByte(byte(pb2data.WlstTml.WlstMru_1100.MeterReadingDate + 0x33))
									d.WriteByte(0x00 + 0x33)
									d.WriteByte(0x29 + 0x33)
									d.WriteByte(0x00 + 0x33)
								case 3:
									d.WriteByte(byte(pb2data.WlstTml.WlstMru_1100.MeterReadingDate + 0x33))
									d.WriteByte(0x00 + 0x33)
									d.WriteByte(0x3d + 0x33)
									d.WriteByte(0x00 + 0x33)
								case 4:
									d.WriteByte(byte(pb2data.WlstTml.WlstMru_1100.MeterReadingDate + 0x33))
									d.WriteByte(0x00 + 0x33)
									d.WriteByte(0x01 + 0x33)
									d.WriteByte(0x00 + 0x33)
								case 5:
									d.WriteByte(byte(pb2data.WlstTml.WlstMru_1100.MeterReadingDate + 0x33))
									d.WriteByte(0x00 + 0x33)
									d.WriteByte(0x00 + 0x33)
									d.WriteByte(0x00 + 0x33)
								default:
									d.WriteByte(byte(pb2data.WlstTml.WlstMru_1100.MeterReadingDate + 0x33))
									d.WriteByte(0x00 + 0x33)
									d.WriteByte(0x00 + 0x33)
									d.WriteByte(0x00 + 0x33)
								}
							} else { // 1997
								d.WriteByte(0x1)
								d.WriteByte(0x2)
								switch pb2data.WlstTml.WlstMru_1100.MeterReadingType {
								case 1: // d0=00110000
									d.WriteByte(0x34)
									d.WriteByte(0x17)
								case 2: // D0=01010000
									d.WriteByte(0x35)
									d.WriteByte(0x17)
								case 3: // D0=01100000
									d.WriteByte(0x36)
									d.WriteByte(0x17)
								case 4: // D0=00010000
									d.WriteByte(gopsu.String2Int8("00010000", 2) + 0x33)
									d.WriteByte(gopsu.String2Int8(fmt.Sprintf("1001%02b00", pb2data.WlstTml.WlstMru_1100.MeterReadingDate), 2) + 0x33)
								case 5: // D0=00010000
									d.WriteByte(gopsu.String2Int8("00000000", 2) + 0x33)
									d.WriteByte(gopsu.String2Int8(fmt.Sprintf("1001%02b00", pb2data.WlstTml.WlstMru_1100.MeterReadingDate), 2) + 0x33)
								default:
									d.WriteByte(gopsu.String2Int8("00000000", 2) + 0x33)
									d.WriteByte(gopsu.String2Int8(fmt.Sprintf("1001%02b00", pb2data.WlstTml.WlstMru_1100.MeterReadingDate), 2) + 0x33)
								}
							}
							d.WriteByte(byte(pb2data.WlstTml.WlstMru_1100.BaudRate))
						case "1300": // 读地址
							br = byte(pb2data.WlstTml.WlstMru_1300.BaudRate)
							for _, v := range pb2data.WlstTml.WlstMru_1300.Addr {
								d.WriteByte(byte(v))
							}
							d.WriteByte(0x13)
							d.WriteByte(0x0)
							d.WriteByte(byte(pb2data.WlstTml.WlstMru_1300.BaudRate))
						default:
							getprotocol = false
						}
					case "rtu": // 终端
						switch scmd[2] {
						case "705b": // 读取硬件信息
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_705B.CmdIdx))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_705B.CmdType))
						case "7020": // 读取电能计量/经纬度等辅助数据
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7020.CmdIdx))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7020.CmdType))
						case "4111": // 发送电能板互感比参数,下发时先/5
							d.WriteByte(0x11)
							for i := 0; i < 3; i++ {
								d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4111.Transformers[i] / 5))
							}
						case "705a": // 新版招测参数
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_705A.CmdIdx))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_705A.CmdType))
						case "4000": // 发送工作参数
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4000.WorkMark))
							d.WriteByte(2)
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4000.KeepAlive))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4000.AlarmCycle))
							d.WriteByte(5)
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4000.XLoopCount[1]))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4000.XLoopCount[0]))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4000.XLoopCount[2]))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4000.AlarmDelay))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4000.XLoopCount[3]))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4000.XLoopCount[4]))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4000.XLoopCount[5]))
							if len(pb2data.WlstTml.WlstRtu_4000.XLoopCount) > 6 {
								d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4000.XLoopCount[6]))
								d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4000.XLoopCount[7]))
							}
						case "4101": // 发送模拟量输入显示参数
							d.WriteByte(0x01)
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4101.AnalogSum + 1))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4101.VoltageRange / 5))
							d.Write(Single2Tribytes(float64(pb2data.WlstTml.WlstRtu_4101.VoltageRange) / 0x3ff0))
							// d.WriteByte(0)
							// d.WriteByte(0)
							// d.WriteByte(0)
							l := pb2data.WlstTml.WlstRtu_4101.AnalogSum
							for i := int32(0); i < l; i++ {
								d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4101.XCurrentRange[i] / 5))
								d.Write(Single2Tribytes(float64(pb2data.WlstTml.WlstRtu_4101.XCurrentRange[i]) / 0x3ff0))
								// d.WriteByte(0)
								// d.WriteByte(0)
								// d.WriteByte(0)
							}
						case "4102":
							d.WriteByte(0x02)
						case "4104":
							d.WriteByte(0x04)
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4104.SwitchinSum))
							l := pb2data.WlstTml.WlstRtu_4104.SwitchinSum
							for i := int32(0); i < l; i++ {
								d.WriteByte(gopsu.String2Int8(
									fmt.Sprintf("%04b%04b", pb2data.WlstTml.WlstRtu_4104.XSwitchVector[i]-1,
										pb2data.WlstTml.WlstRtu_4104.XSwitchHopping[i]*4), 2))
							}
						case "4108":
							d.WriteByte(0x08)
						case "4110":
							d.WriteByte(0x10)
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4110.SwitchInSum))
						case "4201": // 发送模拟量输入矢量参数
							d.WriteByte(0x01)
							d.WriteByte(0x00)
							l := pb2data.WlstTml.WlstRtu_4201.AnalogSum
							for i := int32(0); i < l; i++ {
								d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4201.XAnalogVector[i] - 1))
							}
						case "4202":
							d.WriteByte(0x02)
						case "4204":
							d.WriteByte(0x04)
							l := pb2data.WlstTml.WlstRtu_4204.SwitchInSum
							for i := int32(0); i < l; i++ {
								d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4204.XSwitchInVector[i] - 1))
							}
						case "4208":
							d.WriteByte(0x08)
						case "4210":
							d.WriteByte(0x10)
							l := pb2data.WlstTml.WlstRtu_4210.SwitchOutSum
							for i := int32(0); i < l; i++ {
								d.WriteByte(byte(pb2data.WlstTml.WlstRtu_4210.XSwitchOutVector[i] - 1))
							}
						case "4400", "4401": // 发送上下限参数
							d.WriteByte(0x01)
							d.WriteByte(byte(int(pb2data.WlstTml.WlstRtu_4401.LowerVoltageLimit*1.0/pb2data.WlstTml.WlstRtu_4401.VoltageRange*0x3ff0) & 0xff))
							d.WriteByte(byte(int(pb2data.WlstTml.WlstRtu_4401.LowerVoltageLimit*1.0/pb2data.WlstTml.WlstRtu_4401.VoltageRange*0x3ff0/256) & 0xff))
							d.WriteByte(byte(int(pb2data.WlstTml.WlstRtu_4401.UpperVoltageLimit*1.0/pb2data.WlstTml.WlstRtu_4401.VoltageRange*0x3ff0) & 0xff))
							d.WriteByte(byte(int(pb2data.WlstTml.WlstRtu_4401.UpperVoltageLimit*1.0/pb2data.WlstTml.WlstRtu_4401.VoltageRange*0x3ff0/256) & 0xff))

							for i := int32(0); i < pb2data.WlstTml.WlstRtu_4401.AnalogSum; i++ {
								if pb2data.WlstTml.WlstRtu_4401.XCurrentRange[i] > 0 {
									d.WriteByte(byte(int(pb2data.WlstTml.WlstRtu_4401.XLowerCurrentLimit[i]*1.0/pb2data.WlstTml.WlstRtu_4401.XCurrentRange[i]*0x3ff0) & 0xff))
									d.WriteByte(byte(int(pb2data.WlstTml.WlstRtu_4401.XLowerCurrentLimit[i]*1.0/pb2data.WlstTml.WlstRtu_4401.XCurrentRange[i]*0x3ff0/256) & 0xff))
									d.WriteByte(byte(int(pb2data.WlstTml.WlstRtu_4401.XUpperCurrentLimit[i]*1.0/pb2data.WlstTml.WlstRtu_4401.XCurrentRange[i]*0x3ff0) & 0xff))
									d.WriteByte(byte(int(pb2data.WlstTml.WlstRtu_4401.XUpperCurrentLimit[i]*1.0/pb2data.WlstTml.WlstRtu_4401.XCurrentRange[i]*0x3ff0/256) & 0xff))
								} else {
									d.WriteByte(0)
									d.WriteByte(0)
									d.WriteByte(0)
									d.WriteByte(0)
								}
							}
						case "6100": // 发送电压参数
							a := make([]int32, 36)
							for i := 0; i < 36; i++ {
								a[i] = 0
							}
							copy(a, pb2data.WlstTml.WlstRtu_6100.XVoltagePhase)
							for i := 0; i < 36; i += 4 {
								d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%02b%02b%02b%02b", a[i+3], a[i+2], a[i+1], a[i]), 2))
							}
						case "2200", "2210": // 单回路开关灯
							d.WriteByte(0x10)
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_2210.KNo - 1))
							if pb2data.WlstTml.WlstRtu_2210.Operation == 1 {
								d.WriteByte(0xff)
							} else {
								d.WriteByte(0)
							}
						case "4b00": // 组合开关灯
							for k, v := range pb2data.WlstTml.WlstRtu_4B00.Operation {
								d22 := make([]byte, 0, 3)
								d22 = append(d22, 0x10)
								d22 = append(d22, byte(k))
								switch v {
								case 1:
									d.WriteByte(0xff)
									d22 = append(d22, 0xff)
								case 0:
									d.WriteByte(0)
									d22 = append(d22, byte(v))
								case 2:
									d.WriteByte(2)
								}
								if len(xaddrs) > 0 && len(d22) == 3 {
									for k, v := range xaddrs {
										f := &Fwd{
											DataMsg: DoCommand(byte(pb2data.Head.Ver), byte(pb2data.Head.Tver), tra, v, pb2data.Args.Cid, "wlst.rtu.2200", d22, 0, 0),
											// DataMsg:  gopsu.Bytes2String(DoCommand(byte(pb2data.Head.Ver), byte(pb2data.Head.Tver), tra, v, pb2data.Args.Cid, "wlst.rtu.2200", d22, 0, 0), "-"),
											DataDst:  fmt.Sprintf("%s-%d", strings.Join(scmd[:2], "-"), v),
											DataCmd:  "wlst.rtu.2200",
											DataSP:   byte(pb2data.Head.Ret),
											DataPT:   3000,
											DataType: DataTypeBytes,
											Job:      JobSend,
											Tra:      tra,
											Addr:     v,
											DstType:  1,
										}
										if len(pb2data.Args.Sims) > k {
											f.DstIMEI = pb2data.Args.Sims[k]
										}
										lstf = append(lstf, f)
									}
								}
							}
						case "1200": // 对时
							if dp.TimerNoSec {
								d.Write(GetServerTimeMsg(0, 1, false, true))
							} else {
								d.Write(GetServerTimeMsg(0, 1, true, true))
							}
							// a := strings.Split(pb2data.WlstTml.WlstRtu_1200.TmlDate, " ")
							// y := strings.Split(a[0], "-")
							// h := strings.Split(a[1], ":")
							// d.WriteByte(byte(gopsu.String2Int32(y[0], 10) - 2000))
							// // 为兼容老设备，不发秒字节
							// d.Write([]byte{gopsu.String2Int8(y[1], 10), gopsu.String2Int8(y[2], 10), gopsu.String2Int8(h[0], 10), gopsu.String2Int8(h[1], 10), gopsu.String2Int8(a[2], 10)})
						case "4c00": // 胶南节能
							switch pb2data.WlstTml.WlstRtu_4C00.Status {
							case 1:
								d.WriteByte(0xcc)
							case 2:
								d.WriteByte(0x55)
							case 3:
								d.WriteByte(0x33)
							case 4:
								d.WriteByte(0xaa)
							default:
								d.WriteByte(0xf)
							}
						case "3100": // 设置周设置1-3
							for i := 0; i < 7; i++ {
								t := strings.Split(pb2data.WlstTml.WlstRtu_3100.XK1OptTime[i], "-")
								h := gopsu.String2Int8(t[0][:2], 10)
								m := gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_3100.XK2OptTime[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_3100.XK3OptTime[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_3100.XCityPayTime[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_3100.XSelfPayTime[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
							}
							d.WriteByte(0)
						case "5800": // 设置周设置4-6
							for i := 0; i < 7; i++ {
								t := strings.Split(pb2data.WlstTml.WlstRtu_5800.XK4OptTime[i], "-")
								h := gopsu.String2Int8(t[0][:2], 10)
								m := gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_5800.XK5OptTime[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_5800.XK6OptTime[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
							}
							d.WriteByte(0)
						case "6800": // 设置周设置7-8
							for i := 0; i < 7; i++ {
								t := strings.Split(pb2data.WlstTml.WlstRtu_6800.XK7OptTime[i], "-")
								h := gopsu.String2Int8(t[0][:2], 10)
								m := gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_6800.XK8OptTime[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
							}
							d.WriteByte(0)
						case "4600": // 设置节假日设置1-4/5-8
							for i := 0; i < 4; i++ {
								t := strings.Split(pb2data.WlstTml.WlstRtu_4600.XHolidays[i], "-")
								h := gopsu.String2Int8(t[0][:2], 10)
								m := gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_4600.XK1Time[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_4600.XK2Time[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_4600.XK3Time[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_4600.XK4Time[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_4600.XK5Time[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_4600.XK6Time[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								if len(pb2data.WlstTml.WlstRtu_4600.XK7Time) > 0 {
									if pb2data.WlstTml.WlstRtu_4600.XK7Time[i] != "-1" {
										t = strings.Split(pb2data.WlstTml.WlstRtu_4600.XK7Time[i], "-")
										h = gopsu.String2Int8(t[0][:2], 10)
										m = gopsu.String2Int8(t[0][2:], 10)
										d.WriteByte(gopsu.Int82Bcd(h))
										d.WriteByte(gopsu.Int82Bcd(m))
										h = gopsu.String2Int8(t[1][:2], 10)
										m = gopsu.String2Int8(t[1][2:], 10)
										d.WriteByte(gopsu.Int82Bcd(h))
										d.WriteByte(gopsu.Int82Bcd(m))
									}
								}
								if len(pb2data.WlstTml.WlstRtu_4600.XK8Time) > 0 {
									if pb2data.WlstTml.WlstRtu_4600.XK8Time[i] != "-1" {
										t = strings.Split(pb2data.WlstTml.WlstRtu_4600.XK8Time[i], "-")
										h = gopsu.String2Int8(t[0][:2], 10)
										m = gopsu.String2Int8(t[0][2:], 10)
										d.WriteByte(gopsu.Int82Bcd(h))
										d.WriteByte(gopsu.Int82Bcd(m))
										h = gopsu.String2Int8(t[1][:2], 10)
										m = gopsu.String2Int8(t[1][2:], 10)
										d.WriteByte(gopsu.Int82Bcd(h))
										d.WriteByte(gopsu.Int82Bcd(m))
									}
								}
								tt := pb2data.WlstTml.WlstRtu_4600.XCityPayTime[i]
								h = gopsu.String2Int8(tt[:2], 10)
								m = gopsu.String2Int8(tt[2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								tt = pb2data.WlstTml.WlstRtu_4600.XSelfPayTime[i]
								h = gopsu.String2Int8(tt[:2], 10)
								m = gopsu.String2Int8(tt[2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
							}
							d.WriteByte(0)
						case "6500":
							for i := 0; i < 4; i++ {
								t := strings.Split(pb2data.WlstTml.WlstRtu_6500.XHolidays[i], "-")
								h := gopsu.String2Int8(t[0][:2], 10)
								m := gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_6500.XK1Time[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_6500.XK2Time[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_6500.XK3Time[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_6500.XK4Time[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_6500.XK5Time[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								t = strings.Split(pb2data.WlstTml.WlstRtu_6500.XK6Time[i], "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								if len(pb2data.WlstTml.WlstRtu_6500.XK7Time) > 0 {
									if pb2data.WlstTml.WlstRtu_6500.XK7Time[i] != "-1" {
										t = strings.Split(pb2data.WlstTml.WlstRtu_6500.XK7Time[i], "-")
										h = gopsu.String2Int8(t[0][:2], 10)
										m = gopsu.String2Int8(t[0][2:], 10)
										d.WriteByte(gopsu.Int82Bcd(h))
										d.WriteByte(gopsu.Int82Bcd(m))
										h = gopsu.String2Int8(t[1][:2], 10)
										m = gopsu.String2Int8(t[1][2:], 10)
										d.WriteByte(gopsu.Int82Bcd(h))
										d.WriteByte(gopsu.Int82Bcd(m))
									}
								}
								if len(pb2data.WlstTml.WlstRtu_6500.XK8Time) > 0 {
									if pb2data.WlstTml.WlstRtu_6500.XK8Time[i] != "-1" {
										t = strings.Split(pb2data.WlstTml.WlstRtu_6500.XK8Time[i], "-")
										h = gopsu.String2Int8(t[0][:2], 10)
										m = gopsu.String2Int8(t[0][2:], 10)
										d.WriteByte(gopsu.Int82Bcd(h))
										d.WriteByte(gopsu.Int82Bcd(m))
										h = gopsu.String2Int8(t[1][:2], 10)
										m = gopsu.String2Int8(t[1][2:], 10)
										d.WriteByte(gopsu.Int82Bcd(h))
										d.WriteByte(gopsu.Int82Bcd(m))
									}
								}
								tt := pb2data.WlstTml.WlstRtu_6500.XCityPayTime[i]
								h = gopsu.String2Int8(tt[:2], 10)
								m = gopsu.String2Int8(tt[2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								tt = pb2data.WlstTml.WlstRtu_6500.XSelfPayTime[i]
								h = gopsu.String2Int8(tt[:2], 10)
								m = gopsu.String2Int8(tt[2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
							}
							d.WriteByte(0)
						case "gpsq": // 采集信息
							d.Write([]byte(SendGpsAT))
						case "7800": // 招测事件记录
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7800.EventType))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7800.EventClass))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7800.DataNum))
							y, m, dd, h, mm, _, _ := gopsu.SplitDateTime(pb2data.WlstTml.WlstRtu_7800.DtStart)
							d.WriteByte(y)
							d.WriteByte(m)
							d.WriteByte(dd)
							d.WriteByte(h)
							d.WriteByte(mm)
							y, m, dd, h, mm, _, _ = gopsu.SplitDateTime(pb2data.WlstTml.WlstRtu_7800.DtEnd)
							d.WriteByte(y)
							d.WriteByte(m)
							d.WriteByte(dd)
							d.WriteByte(h)
							d.WriteByte(mm)
						case "1900": // 修改设备地址
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_1900.Addr % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_1900.Addr / 256))
						case "7010": // 复位终端 1-复位终端，2-恢复出厂参数，3-复位通信模块，4-火零不平衡复位
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7010.CmdIdx))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7010.DataMark))
						case "7060": // 设置年开关灯时间
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7060.CmdIdx))
							_, m, dd, _, _, _, _ := gopsu.SplitDateTime(pb2data.WlstTml.WlstRtu_7060.DtStart)
							d.WriteByte(m)
							d.WriteByte(dd)
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7060.Days))
							// xdatah := make([]byte, 0)
							xdata := make([]byte, 0)
							loopmark := strings.Split("0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0", "-")
							for _, v := range pb2data.WlstTml.WlstRtu_7060.YearCtrl {
								loopmark[16-v.LoopNo] = "1"
								if v.TimeCount == 0 {
									xdata = append(xdata, byte(0))
									continue
								}
								xdata = append(xdata, byte(v.TimeCount))
								for _, vv := range v.OptTime {
									xdata = append(xdata, byte(vv/60))
									xdata = append(xdata, byte(vv%60))
								}
							}
							// xdatah = append(xdatah, gopsu.StringSlice2Int8(loopmark[8:]))
							// xdatah = append(xdatah, gopsu.StringSlice2Int8(loopmark[:8]))
							// xdatah = append(xdatah, xdata...)
							d.WriteByte(gopsu.String2Int8(strings.Join(loopmark, "")[8:], 2))
							d.WriteByte(gopsu.String2Int8(strings.Join(loopmark, "")[:8], 2))
							d.Write(xdata)
						case "7061": // 查询年开关灯时间
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7061.CmdIdx))
							_, m, dd, _, _, _, _ := gopsu.SplitDateTime(pb2data.WlstTml.WlstRtu_7061.DtStart)
							d.WriteByte(m)
							d.WriteByte(dd)
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7061.Days))
							loopmark := strings.Split("0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0", "-")
							for _, v := range pb2data.WlstTml.WlstRtu_7061.LoopNo {
								loopmark[16-v] = "1"
							}
							d.WriteByte(gopsu.String2Int8(strings.Join(loopmark, "")[8:], 2))
							d.WriteByte(gopsu.String2Int8(strings.Join(loopmark, "")[:8], 2))
						case "7053": // 读取sd卡数据
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7053.CmdIdx))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7053.RecordType))
							y, m, dd, h, mm, ss, _ := gopsu.SplitDateTime(pb2data.WlstTml.WlstRtu_7053.DtStart)
							d.WriteByte(byte((int(y) + 2000) % 256))
							d.WriteByte(byte((int(y) + 2000) / 256))
							d.WriteByte(m)
							d.WriteByte(dd)
							d.WriteByte(h)
							d.WriteByte(mm)
							d.WriteByte(ss)
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7053.RecordCount))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7053.RecordDistance % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7053.RecordDistance / 256 % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7053.RecordDistance / 256 / 256 % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7053.RecordDistance / 256 / 256 / 256 % 256))
						case "7021": // 设置终端参数(火零不平衡,1-24路周控制时间表)
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7021.CmdIdx))
							switch pb2data.WlstTml.WlstRtu_7021.DataType {
							case 1: //火零不平衡
								d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7021.DataType))
								loopmark := strings.Split("0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0", "-")
								basevalue := make([]byte, 12)
								alarmvalue := make([]byte, 12)
								breakvalue := make([]byte, 12)
								for _, v := range pb2data.WlstTml.WlstRtu_7021.Argsln {
									loopmark[v.LoopNo-1] = "1"
									basevalue[v.LoopNo-1] = byte(v.BaseValue)
									alarmvalue[v.LoopNo-1] = byte(v.AlarmValue)
									breakvalue[v.LoopNo-1] = byte(v.BreakValue)
								}
								ss := gopsu.ReverseString(strings.Join(loopmark, ""))
								d.WriteByte(gopsu.String2Int8(ss[8:], 2))
								d.WriteByte(gopsu.String2Int8(ss[:8], 2))
								for i := 0; i < 12; i++ {
									d.WriteByte(byte(basevalue[i]))
								}
								for i := 0; i < 12; i++ {
									d.WriteByte(byte(alarmvalue[i]))
								}
								for i := 0; i < 12; i++ {
									d.WriteByte(byte(breakvalue[i]))
								}
							case 2: //1-24路周控制时间表 武汉亮化
								d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7021.DataType))
								d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7021.LoopType))
								for _, v := range pb2data.WlstTml.WlstRtu_7021.Argswc {
									d.WriteByte(gopsu.Int82Bcd(byte(v.L1On / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L1On % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L1Off / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L1Off % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L2On / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L2On % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L2Off / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L2Off % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L3On / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L3On % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L3Off / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L3Off % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L4On / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L4On % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L4Off / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L4Off % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L5On / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L5On % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L5Off / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L5Off % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L6On / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L6On % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L6Off / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L6Off % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L7On / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L7On % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L7Off / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L7Off % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L8On / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L8On % 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L8Off / 60)))
									d.WriteByte(gopsu.Int82Bcd(byte(v.L8Off % 60)))
								}
							}
						case "7022": // 读取终端参数(火零不平衡,1-24路周控制时间表))
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7022.CmdIdx))
							switch pb2data.WlstTml.WlstRtu_7022.DataType {
							case 1: //火零不平衡
								d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7022.DataType))
							case 2: //1-24路周控制时间表 武汉亮化
								d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7022.DataType))
								d.WriteByte(0) //1-8回路
							}
						case "7023": // 24路遥控开关灯 武汉亮化
							d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7023.CmdIdx))
							switch pb2data.WlstTml.WlstRtu_7023.DataType {
							case 1:
								d.WriteByte(byte(pb2data.WlstTml.WlstRtu_7023.DataType))
								for _, v := range pb2data.WlstTml.WlstRtu_7023.Argscontrol {
									d.WriteByte(byte(v.LoopNo - 1)) //硬件回路为0-23
									if v.Operation == 0 {
										d.WriteByte(0x00)
									} else if v.Operation == 1 {
										d.WriteByte(0xff)
									}
								}
							}
						case "1300", "2000", "5c00", "3200", "5900", "6900", "5a00", "2500", "4700", "2900", "5d00", "2b00", "7700", "2800", "3900", "6600": // 终端选测/招测版本/招测参数/招测节假日/停运/解除停运
						default:
							getprotocol = false
						}
					case "com": // 模块
						switch scmd[2] {
						case "0000":
							ndatacmd = "wlst.rtu.700a"
							s := fmt.Sprintf("%s:%s:%s:%s:%s", pb2data.WlstCom_0000.ServerIp[:15],
								pb2data.WlstCom_0000.ServerPort[:5],
								pb2data.WlstCom_0000.Apn[:24],
								pb2data.WlstCom_0000.KeepAlive[:3],
								string(pb2data.WlstCom_0000.Type[0]))
							d.Write([]byte(s))
							ndata = append(ndata, 0)
							ndata = append(ndata, []byte(pb2data.WlstCom_0000.Apn[:31])...)
							ndata = append(ndata, 0)
							ips := strings.Split(pb2data.WlstCom_0000.ServerIp, ".")
							for _, v := range ips {
								ndata = append(ndata, gopsu.String2Int8(v, 10))
							}
							ndata = append(ndata, byte(gopsu.String2Int32(pb2data.WlstCom_0000.ServerPort, 10)%256),
								byte(gopsu.String2Int32(pb2data.WlstCom_0000.ServerPort, 10)/256))
							ndata = append(ndata, 0)
							ndata = append(ndata, gopsu.String2Int8(pb2data.WlstCom_0000.KeepAlive[:3], 10)/10)
							ndata = append(ndata, 0, 0, 0, 0, 0, 0, 0x93, 0, 0xff)
							ndata = append(ndata, []byte(pb2data.WlstCom_0000.CdmaUsername[:31])...)
							ndata = append(ndata, 0)
							ndata = append(ndata, []byte(pb2data.WlstCom_0000.CdmaPassword[:31])...)
							ndata = append(ndata, 0, 0xaa, 1, 4, 0, 0, 0, 0x30,
								0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
								0x43, 0x58, 0x4c, 0x4c, 0,
								0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30)
						case "0100":
							d.Write([]byte(pb2data.WlstCom_0000.Sim))
						case "0200":
							ndatacmd = "wlst.rtu.700b"
							ndata = append(ndata, 0)
						case "0c00":
							s := fmt.Sprintf("%s%s", pb2data.WlstCom_0000.CdmaUsername[:29], pb2data.WlstCom_0000.CdmaPassword[:13])
							d.Write([]byte(s))
						case "3e01":
							d.WriteByte(byte(pb2data.WlstCom_3E01.GroupMark))
							for _, v := range pb2data.WlstCom_3E01.ArgsMark {
								d.WriteByte(byte(v))
							}
						case "3e02":
							ndatacmd = "wlst.rtu.700a"
							grpmark := fmt.Sprintf("%08b", pb2data.WlstCom_3E02.GroupMark)
							var g1mark, g2mark, g3mark, g4mark, g5mark string
							j := 0
							if grpmark[7] == 49 {
								g1mark = fmt.Sprintf("%016b", pb2data.WlstCom_3E02.ArgsMark[j])
								j += 2
							}
							if grpmark[6] == 49 {
								g2mark = fmt.Sprintf("%08b%08b", pb2data.WlstCom_3E02.ArgsMark[j+1],
									pb2data.WlstCom_3E02.ArgsMark[j])
								j += 2
							}
							if grpmark[5] == 49 {
								g3mark = fmt.Sprintf("%016b", pb2data.WlstCom_3E02.ArgsMark[j])
								j += 2
							}
							if grpmark[4] == 49 {
								g4mark = fmt.Sprintf("%08b%08b", pb2data.WlstCom_3E02.ArgsMark[j+1],
									pb2data.WlstCom_3E02.ArgsMark[j])
								j += 2
							}
							if grpmark[3] == 49 {
								g5mark = fmt.Sprintf("%016b", pb2data.WlstCom_3E02.ArgsMark[j])
								j += 2
							}
							d.WriteByte(byte(pb2data.WlstCom_3E02.GroupMark))
							for _, v := range pb2data.WlstCom_3E02.ArgsMark {
								d.WriteByte(byte(v))
							}
							if len(g1mark) > 0 {
								if g1mark[15] == 49 {
									d.Write([]byte(pb2data.WlstCom_3E02.Operators.Apn))
								}
								if g1mark[14] == 49 {
									d.Write([]byte(pb2data.WlstCom_3E02.Operators.User))
								}
								if g1mark[13] == 49 {
									d.Write([]byte(pb2data.WlstCom_3E02.Operators.Pwd))
								}
							}
							if len(g2mark) > 0 {
								if g2mark[15] == 49 {
									d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04b%04b", pb2data.WlstCom_3E02.Channel.Channel2Type, pb2data.WlstCom_3E02.Channel.Channel1Type), 2))
								}
								if g2mark[14] == 49 {
									for _, v := range pb2data.WlstCom_3E02.Channel.Channel1Ip {
										d.WriteByte(byte(v))
									}
								}
								if g2mark[13] == 49 {
									d.WriteByte(byte(pb2data.WlstCom_3E02.Channel.Channel1Port / 256))
									d.WriteByte(byte(pb2data.WlstCom_3E02.Channel.Channel1Port % 256))
								}
								if g2mark[12] == 49 {
									d.WriteByte(byte(pb2data.WlstCom_3E02.Channel.Channel1LocalPort / 256))
									d.WriteByte(byte(pb2data.WlstCom_3E02.Channel.Channel1LocalPort % 256))
								}
								if g2mark[11] == 49 {
									for _, v := range pb2data.WlstCom_3E02.Channel.Channel2Ip {
										d.WriteByte(byte(v))
									}
								}
								if g2mark[10] == 49 {
									d.WriteByte(byte(pb2data.WlstCom_3E02.Channel.Channel1Port / 256))
									d.WriteByte(byte(pb2data.WlstCom_3E02.Channel.Channel1Port % 256))
								}
								if g2mark[9] == 49 {
									d.WriteByte(byte(pb2data.WlstCom_3E02.Channel.Channel1LocalPort / 256))
									d.WriteByte(byte(pb2data.WlstCom_3E02.Channel.Channel1LocalPort % 256))
								}
								if g2mark[8] == 49 {
									d.WriteByte(byte(pb2data.WlstCom_3E02.Channel.KeepAlive))
								}
								if g2mark[7] == 49 {
									d.WriteByte(byte(pb2data.WlstCom_3E02.Channel.Idle))
								}
							}
							if len(g3mark) > 0 {
								if g3mark[15] == 49 {
									d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04b%04b", pb2data.WlstCom_3E02.Interface.Port2Br, pb2data.WlstCom_3E02.Interface.Port1Br), 2))
									d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%02b%03b%03b", pb2data.WlstCom_3E02.Interface.WorkMode, pb2data.WlstCom_3E02.Interface.Port2Rc, pb2data.WlstCom_3E02.Interface.Port1Rc), 2))
								}
							}
							if len(g4mark) > 0 {
								if g4mark[15] == 49 {
									d.WriteByte(byte(pb2data.WlstCom_3E02.Sms.ValidCount))
								}
								if g4mark[14] == 49 {
									d.Write([]byte(pb2data.WlstCom_3E02.Sms.Sim[0]))
								}
								if g4mark[4] == 49 {
									d.Write([]byte(pb2data.WlstCom_3E02.Sms.Yecx))
								}
							}
							if len(g5mark) > 0 {
								if g5mark[15] == 49 {
									for _, v := range pb2data.WlstCom_3E02.Address.Addr {
										d.WriteByte(byte(v))
									}
								}
							}
							// 7e 70用数据
							ndata = append(ndata, 0)
							if len(g1mark) > 0 {
								if g1mark[15] == 49 {
									for _, v := range []byte(pb2data.WlstCom_3E02.Operators.Apn) {
										if v == 0 {
											break
										}
										ndata = append(ndata, v)
									}
									ndata = append(ndata, 0)
									// ndata = append(ndata, []byte(pb2data.WlstCom_3E02.Operators.Apn)...)
								} else {
									ndata = append(ndata, []byte("CMNET")...)
									ndata = append(ndata, 0)
									// for i := 0; i < 32; i++ {
									// 	ndata = append(ndata, 0)
								}
							}
							if len(g2mark) > 0 {
								if g2mark[14] == 49 {
									for _, v := range pb2data.WlstCom_3E02.Channel.Channel1Ip {
										ndata = append(ndata, byte(v))
									}
								} else {
									ndata = append(ndata, 180, 153, 108, 83)
								}
								if g2mark[13] == 49 {
									ndata = append(ndata, byte(pb2data.WlstCom_3E02.Channel.Channel1Port%256),
										byte(pb2data.WlstCom_3E02.Channel.Channel1Port/256))
								} else {
									ndata = append(ndata, byte(10001/256), byte(10001%256))
								}
								if g2mark[15] == 49 {
									ndata = append(ndata, gopsu.String2Int8(fmt.Sprintf("%04b%04b", pb2data.WlstCom_3E02.Channel.Channel2Type, pb2data.WlstCom_3E02.Channel.Channel1Type), 2), 0x07)
								} else {
									ndata = append(ndata, 0, 0x7)
								}
								if g2mark[11] == 49 {
									for _, v := range pb2data.WlstCom_3E02.Channel.Channel2Ip {
										ndata = append(ndata, byte(v))
									}
								} else {
									ndata = append(ndata, 0, 0, 0, 0)
								}
								if g2mark[10] == 49 {
									ndata = append(ndata, byte(pb2data.WlstCom_3E02.Channel.Channel2Port%256),
										byte(pb2data.WlstCom_3E02.Channel.Channel2Port/256))
								} else {
									ndata = append(ndata, 0, 0)
								}
							} else {
								ndata = append(ndata, 180, 153, 108, 83, 10001/256, 10001%256, 0, 7, 0, 0, 0, 0, 0, 0)
							}
							if len(g3mark) > 0 && g3mark[15] == 49 {
								d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04b%04b", pb2data.WlstCom_3E02.Interface.Port2Br, pb2data.WlstCom_3E02.Interface.Port1Br), 2))
								d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%02b%03b%03b", pb2data.WlstCom_3E02.Interface.WorkMode, pb2data.WlstCom_3E02.Interface.Port2Rc, pb2data.WlstCom_3E02.Interface.Port1Rc), 2))
							} else {
								ndata = append(ndata, 0x93, 0x00)
							}
							ndata = append(ndata, 0xff)
							if len(g1mark) > 0 {
								if g2mark[14] == 49 {
									for _, v := range []byte(pb2data.WlstCom_3E02.Operators.User) {
										if v == 0 {
											break
										}
										ndata = append(ndata, v)
									}
									ndata = append(ndata, 0)
									// ndata = append(ndata, []byte(pb2data.WlstCom_3E02.Operators.User)...)
								} else {
									// for i := 0; i < 32; i++ {
									ndata = append(ndata, 0)
									// }
								}
								if g2mark[13] == 49 {
									for _, v := range []byte(pb2data.WlstCom_3E02.Operators.Pwd) {
										if v == 0 {
											break
										}
										ndata = append(ndata, v)
									}
									ndata = append(ndata, 0)
									// ndata = append(ndata, []byte(pb2data.WlstCom_3E02.Operators.Pwd)...)
								} else {
									// for i := 0; i < 32; i++ {
									ndata = append(ndata, 0)
									// }
								}
							} else {
								for i := 0; i < 64; i++ {
									ndata = append(ndata, 0)
								}
							}
							if len(g2mark) > 0 {
								if g2mark[12] == 49 {
									ndata = append(ndata, byte(pb2data.WlstCom_3E02.Channel.Channel1LocalPort/256),
										byte(pb2data.WlstCom_3E02.Channel.Channel1LocalPort%256))
								} else {
									ndata = append(ndata, byte(1024/256), byte(1024%256))
								}
								if g2mark[9] == 49 {
									ndata = append(ndata, byte(pb2data.WlstCom_3E02.Channel.Channel2LocalPort/256),
										byte(pb2data.WlstCom_3E02.Channel.Channel2LocalPort%256))
								} else {
									ndata = append(ndata, 0, 0)
								}
							} else {
								ndata = append(ndata, byte(1024/256), byte(1024%256), 0, 0)
							}
							ndata = append(ndata, 0xaa)
							if len(g4mark) > 0 {
								if g4mark[15] == 49 {
									ndata = append(ndata, byte(pb2data.WlstCom_3E02.Sms.ValidCount))
								} else {
									ndata = append(ndata, 0)
								}
								if g4mark[14] == 49 {
									ndata = append(ndata, []byte(pb2data.WlstCom_3E02.Sms.Sim[0])...)
								} else {
									ndata = append(ndata, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30)
								}
								if g4mark[4] == 49 {
									ndata = append(ndata, []byte(pb2data.WlstCom_3E02.Sms.Yecx)...)
								} else {
									ndata = append(ndata, []byte("CXLL")...)
								}
							} else {
								ndata = append(ndata, 0, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30)
								ndata = append(ndata, []byte("CXLL")...)
							}
							if len(g5mark) > 0 && g5mark[15] == 49 {
								for _, v := range pb2data.WlstCom_3E02.Address.Addr {
									ndata = append(ndata, byte(v))
								}
							}
						case "7006", "7106", "5a06": // 模块远程升级准备
						case "7007", "7107", "5a07": // 模块远程升级状态查询
						case "7008", "7108", "5a08": // 模块远程升级数据
						case "0b00":
						default:
							getprotocol = false
						}
					case "sys": // 系统
						switch scmd[2] {
						case "whois":
						default:
							getprotocol = false
						}
					case "elu": // 漏电
						br = 5
						rc = 0
						switch scmd[2] {
						case "6255": // 设置地址
							d.WriteByte(byte(pb2data.WlstTml.WlstElu_6255.NewAddr))
						case "6256": // 设置运行参数
							loopmark := make([]string, 8)
							xdata := make([]byte, 0)
							for k, v := range pb2data.WlstTml.WlstElu_6256.WorkArgv {
								loopmark[7-k] = fmt.Sprintf("%d", v.LoopMark)
								xdata = append(xdata, byte(v.WorkMode))
								xdata = append(xdata, byte(v.AlarmValueSet%256))
								xdata = append(xdata, byte(v.AlarmValueSet/256))
								xdata = append(xdata, byte((v.OptDelay/10)%256))
								xdata = append(xdata, byte((v.OptDelay/10)/256))
							}
							d.WriteByte(gopsu.String2Int8(strings.Join(loopmark, ""), 2))
							d.Write(xdata)
						case "6257": // 手动操作
							var s string
							for _, v := range pb2data.WlstTml.WlstElu_6257.OptDo {
								s = fmt.Sprintf("%02b", v) + s
								if len(s) == 8 {
									d.WriteByte(gopsu.String2Int8(s, 2))
									s = ""
								}
							}
						case "625a": // 查询事件
							d.WriteByte(byte(pb2data.WlstTml.WlstElu_625A.EventsCount))
						case "625b": // 设置检测门限
							d.WriteByte(byte(pb2data.WlstTml.WlstElu_625B.WatchValueEl % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstElu_625B.WatchValueEl / 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstElu_625B.WatchValueTp % 256))
							d.WriteByte(byte(pb2data.WlstTml.WlstElu_625B.WatchValueTp / 256))
						case "625c": // 设置时钟
							y, m, dd, h, mm, _, _ := gopsu.SplitDateTime(pb2data.WlstTml.WlstElu_625C.DtTimer)
							d.WriteByte(y)
							d.WriteByte(m)
							d.WriteByte(dd)
							d.WriteByte(h)
							d.WriteByte(mm)
						case "6259", "6260", "625d", "625e", "625f": // 选测漏电/温度/招测参数/时钟/复位
						default:
							getprotocol = false
						}
					case "pth": // 透传(远程升级)
						for _, v := range pb2data.Passthrough.PkgData {
							d.WriteByte(byte(v))
						}
						switch pb2data.Passthrough.DataMark {
						case 0xf8, 0x70:
							scmd[1] = "rtu"
						case 0x71, 0x72:
							scmd[1] = "slu"
						case 0x51:
							scmd[1] = "com"
						}
					default:
						getprotocol = false
					}
				case "wxjy":
					switch scmd[1] {
					case "esu":
						switch scmd[2] {
						case "5500", "5600": // 设置时间
							_, _, _, h, m, s, _ := gopsu.SplitDateTime(time.Now().Unix())
							d.WriteByte(h)
							d.WriteByte(m)
							d.WriteByte(s)
							for i := 0; i < 3; i++ {
								d.WriteByte(byte(pb2data.WxjyEsu_5500.XTime[i] / 60))
								d.WriteByte(byte(pb2data.WxjyEsu_5500.XTime[i] % 60))
								d.WriteByte(byte(pb2data.WxjyEsu_5500.XVoltage[i]))
							}
						case "5700": // 选测
							br = 5
							rc = 0x37
						case "5800":
							br = 5
							rc = 0
						default:
							getprotocol = false
						}
					default:
						getprotocol = false
					}
				case "ahhf":
					switch scmd[1] {
					case "rtu":
						switch scmd[2] {
						case "2000": // 选测
							afn := gopsu.String2Int8(fmt.Sprintf("%08b", 0x0c), 2)
							seq := gopsu.String2Int8("00010000", 2)
							d.WriteByte(afn)
							d.WriteByte(seq)
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(gopsu.String2Int8("00000011", 2))
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(0)
						case "6804": // 设置参数
							afn := gopsu.String2Int8(fmt.Sprintf("%08b", 0x04), 2)
							seq := gopsu.String2Int8("00010000", 2)
							d.WriteByte(afn)
							d.WriteByte(seq)
							var xdata1, xdata2, xdata3 = make([]byte, 0), make([]byte, 0), make([]byte, 0)
							x := []string{"0", "0", "0", "0", "0", "0", "0", "0"}
							for _, v := range pb2data.AhhfRtu_6804.DataMark {
								switch v {
								case 3:
									x[5] = "1"
									xdata3 = append(xdata3, byte(int32(pb2data.AhhfRtu_6804.SwitchInLimit.VoltageLowlimit[0]*100)%256),
										byte(int32(pb2data.AhhfRtu_6804.SwitchInLimit.VoltageLowlimit[0]*100)/256),
										byte(int32(pb2data.AhhfRtu_6804.SwitchInLimit.VoltageUplimit[0]*100)%256),
										byte(int32(pb2data.AhhfRtu_6804.SwitchInLimit.VoltageUplimit[0]*100)/256),
										byte(pb2data.AhhfRtu_6804.SwitchInLimit.LoopTotal))
									for k, v := range pb2data.AhhfRtu_6804.SwitchInLimit.CurrentLowlimit {
										xdata3 = append(xdata3, byte(int(v)%256), byte(int(v)/256))
										xdata3 = append(xdata3, byte(int(pb2data.AhhfRtu_6804.SwitchInLimit.CurrentUplimit[k])%256),
											byte(int(pb2data.AhhfRtu_6804.SwitchInLimit.CurrentUplimit[k])/256))
									}
								case 2:
									x[6] = "1"
									xdata2 = append(xdata2, byte(pb2data.AhhfRtu_6804.SwitchIn.VoltageTransformer),
										byte(pb2data.AhhfRtu_6804.SwitchIn.LoopTotal))
									for k, v := range pb2data.AhhfRtu_6804.SwitchIn.CurrentTransformer {
										xdata2 = append(xdata2, byte(v/5), byte(pb2data.AhhfRtu_6804.SwitchIn.CurrentPhase[k]))
									}
								case 1:
									x[7] = "1"
									xdata1 = append(xdata1, byte(pb2data.AhhfRtu_6804.SwitchOut.SwitchOutTotal))
									for _, v := range pb2data.AhhfRtu_6804.SwitchOut.SwitchOutLoop {
										xdata1 = append(xdata1, byte(v))
									}
								}
							}
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(gopsu.String2Int8(strings.Join(x, ""), 2))
							d.WriteByte(0)
							xd := len(xdata1) + len(xdata2) + len(xdata3)
							d.WriteByte(byte(xd % 256))
							d.WriteByte(byte(xd / 256))
							d.Write(xdata1)
							d.Write(xdata2)
							d.Write(xdata3)
						case "680a": // 读取参数
							afn := gopsu.String2Int8(fmt.Sprintf("%08b", 0x0a), 2)
							seq := gopsu.String2Int8("00010000", 2)
							d.WriteByte(afn)
							d.WriteByte(seq)
							x := []string{"0", "0", "0", "0", "0", "0", "0", "0"}
							for _, v := range pb2data.AhhfRtu_680A.DataMark {
								switch v {
								case 3:
									x[5] = "1"
								case 2:
									x[6] = "1"
								case 1:
									x[7] = "1"
								}
							}
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(gopsu.StringSlice2Int8(x))
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(0)
						case "1200": // 设置时钟
							afn := gopsu.String2Int8(fmt.Sprintf("%08b", 0x04), 2)
							seq := gopsu.String2Int8("00010000", 2)
							d.WriteByte(afn)
							d.WriteByte(seq)
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(gopsu.String2Int8("00001000", 2))
							d.WriteByte(0)
							y, m, dd, h, mm, s, wd := gopsu.SplitDateTime(time.Now().Unix())
							d.WriteByte(7 % 256)
							d.WriteByte(7 / 256)
							d.WriteByte(y)
							d.WriteByte(m)
							d.WriteByte(dd)
							d.WriteByte(h)
							d.WriteByte(mm)
							d.WriteByte(s)
							d.WriteByte(wd)
						case "1300": // 读取时钟
							afn := gopsu.String2Int8(fmt.Sprintf("%08b", 0x0a), 2)
							seq := gopsu.String2Int8("00010000", 2)
							d.WriteByte(afn)
							d.WriteByte(seq)
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(gopsu.String2Int8("00001000", 2))
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(0)
						case "7060": // 设置年时间
							afn := gopsu.String2Int8(fmt.Sprintf("%08b", 0x04), 2)
							seq := gopsu.String2Int8(fmt.Sprintf("0001%04b", pb2data.WlstTml.WlstRtu_7060.CmdIdx), 2)
							d.WriteByte(afn)
							d.WriteByte(seq)
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(gopsu.String2Int8("00000001", 2))
							d.WriteByte(1)
							_, m, dd, _, _, _, _ := gopsu.SplitDateTime(pb2data.WlstTml.WlstRtu_7060.DtStart)
							xdatah := make([]byte, 0)
							xdatah = append(xdatah, m, dd, byte(pb2data.WlstTml.WlstRtu_7060.Days))
							xdata := make([]byte, 0)
							loopmark := strings.Split("0-0-0-0-0-0-0-0-0-0-0-0-0-0-0-0", "-")
							for _, v := range pb2data.WlstTml.WlstRtu_7060.YearCtrl {
								if v.TimeCount == 0 {
									continue
								}
								loopmark[16-v.LoopNo] = "1"
								xdata = append(xdata, byte(v.TimeCount))
								for _, v := range v.OptTime {
									xdata = append(xdata, byte(v/60), byte(v%60))
								}
							}
							xdatah = append(xdatah, gopsu.StringSlice2Int8(loopmark[8:]))
							xdatah = append(xdatah, gopsu.StringSlice2Int8(loopmark[:8]))
							xdatah = append(xdatah, xdata...)
							d.WriteByte(byte(len(xdatah) % 256))
							d.WriteByte(byte(len(xdatah) / 256))
							d.Write(xdatah)
						case "7061": // 读取年时间
							afn := gopsu.String2Int8(fmt.Sprintf("%08b", 0x0a), 2)
							seq := gopsu.String2Int8(fmt.Sprintf("0001%04b", pb2data.WlstTml.WlstRtu_7060.CmdIdx), 2)
							d.WriteByte(afn)
							d.WriteByte(seq)
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(gopsu.String2Int8("00000001", 2))
							d.WriteByte(1)
							d.WriteByte(0)
							d.WriteByte(0)
						case "4b00": // 开关灯
							afn := gopsu.String2Int8(fmt.Sprintf("%08b", 0x05), 2)
							seq := gopsu.String2Int8("00010000", 2)
							d.WriteByte(afn)
							d.WriteByte(seq)
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(1)
							d.WriteByte(0)
							xdata := make([]byte, 0)
							xdata = append(xdata, byte(len(pb2data.WlstTml.WlstRtu_4B00.Operation)))
							for _, v := range pb2data.WlstTml.WlstRtu_4B00.Operation {
								xdata = append(xdata, byte(v))
							}
							d.WriteByte(byte(len(xdata) % 256))
							d.WriteByte(byte(len(xdata) / 256))
							d.Write(xdata)
						case "5c00": // 读取版本
							afn := gopsu.String2Int8(fmt.Sprintf("%08b", 0x09), 2)
							seq := gopsu.String2Int8("00010000", 2)
							d.WriteByte(afn)
							d.WriteByte(seq)
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(gopsu.String2Int8("00000001", 2))
							d.WriteByte(0)
							d.WriteByte(0)
							d.WriteByte(0)
						default:
							getprotocol = false
						}
					default:
						getprotocol = false
					}
				default:
					getprotocol = false
				}
				if getprotocol {
					for k, v := range xaddrs {
						f := &Fwd{
							DataMsg: DoCommand(byte(pb2data.Head.Ver), byte(pb2data.Head.Tver), tra, v, pb2data.Args.Cid, cmd, d.Bytes(), br, rc),
							// DataMsg:  gopsu.Bytes2String(DoCommand(byte(pb2data.Head.Ver), byte(pb2data.Head.Tver), tra, v, pb2data.Args.Cid, cmd, d.Bytes(), br, rc), "-"),
							DataDst:  fmt.Sprintf("%s-%d", strings.Join(scmd[:2], "-"), v),
							DataCmd:  cmd,
							DataSP:   byte(pb2data.Head.Ret),
							DataPT:   3000,
							DataType: DataTypeBytes,
							Job:      JobSend,
							Tra:      tra,
							Addr:     v,
							DstType:  1,
							// Src:      fmt.Sprintf("%v", pb2data),
						}
						if cmd == "wlst.rtu.1900" {
							f.DstIP = pb2data.WlstTml.WlstRtu_1900.TmlIp
						}
						if scmd[2][:2] == "fe" {
							f.DataPT = 2000
						}
						if scmd[0] == "wlst" && scmd[1] == "rtu" && scmd[2][:2] != "70" && scmd[2][:2] != "fe" {
							f.DataPT = 3000
						}
						if tra == 2 {
							f.DataDst = fmt.Sprintf("wlst-rtu-%d", v)
							f.DataPT = 7000
						}
						// 采用imei寻址
						if len(pb2data.Args.Sims) > k {
							f.DstIMEI = pb2data.Args.Sims[k]
						}
						if scmd[2] == "3100" ||
							scmd[2] == "5800" ||
							scmd[2] == "6800" ||
							scmd[2] == "7021" {
							f.DataPT = 10000
						}
						// 发送主板通讯参数修改
						if len(ndata) > 0 {
							ff := &Fwd{
								DataCmd: ndatacmd,
								DataMsg: DoCommand(byte(pb2data.Head.Ver), byte(pb2data.Head.Tver), tra, v, pb2data.Args.Cid, ndatacmd, ndata, br, rc),
								// DataMsg:  gopsu.Bytes2String(DoCommand(byte(pb2data.Head.Ver), byte(pb2data.Head.Tver), tra, v, pb2data.Args.Cid, cmd, ndata, br, rc), "-"),
								DataSP:   SendLevelHigh,
								DataDst:  fmt.Sprintf("wlst-rtu-%d", v),
								DataPT:   3000,
								DataType: DataTypeBytes,
								Job:      JobSend,
								Tra:      TraDirect,
								Addr:     v,
								Src:      fmt.Sprintf("%v", pb2data),
								DstType:  1,
							}
							lstf = append(lstf, ff)
						}
						// 发送模块通讯参数修改
						lstf = append(lstf, f)
						// 发送复位
						if cmd == "wlst.com.3e02" {
							ff := &Fwd{
								DataCmd:  "wlst.rtu.7010",
								DataMsg:  Send7010,
								DataSP:   SendLevelNormal,
								DataDst:  fmt.Sprintf("wlst-rtu-%d", v),
								DataPT:   500,
								DataType: DataTypeBytes,
								Job:      JobSend,
								Tra:      TraDirect,
								Addr:     v,
								Src:      fmt.Sprintf("%v", pb2data),
								DstType:  1,
							}
							lstf = append(lstf, ff)
							ff = &Fwd{
								DataCmd:  "wlst.com.3e09",
								DataMsg:  Send3e3c09,
								DataSP:   SendLevelNormal,
								DataDst:  fmt.Sprintf("wlst-com-%d", v),
								DataPT:   500,
								DataType: DataTypeBytes,
								Job:      JobSend,
								Tra:      TraDirect,
								Addr:     v,
								Src:      fmt.Sprintf("%v", pb2data),
								DstType:  1,
							}
							lstf = append(lstf, ff)
						}
					}
				}
			case 4:
				pb2data.Head.Src = 1
				pb2data.Head.Mod = 2
				switch cmd {
				case "wlst.gps.0000":
					// todo 修改系统时钟

				default:
					getprotocol = false
				}
				if getprotocol {
					f := &Fwd{
						DataCmd:  cmd,
						DataMsg:  CodePb2(pb2data),
						DstType:  SockData,
						DataType: DataTypeBase64,
						DataDst:  "2",
						DataSP:   1,
					}
					lstf = append(lstf, f)
				}
			default:
				getprotocol = false
			}
		default:
			getprotocol = false
		}
	default:
		getprotocol = false
	}
	if !getprotocol {
		f := &Fwd{
			DataCmd: cmd,
			Src:     fmt.Sprintf("%v", pb2data),
			Ex:      "unknow protocol",
			DstType: byte(pb2data.Head.Src),
		}
		lstf = append(lstf, f)
	}
	return lstf
}

// ProcessOpen 处理五零盛同国标协议
func (dp *DataProcessor) ProcessOpen(b *[]byte) (lstf []*Fwd) {
	defer func() {
		if ex := recover(); ex != nil {
			f := &Fwd{
				Ex: fmt.Sprintf("%+v", errors.WithStack(ex.(error))),
			}
			lstf = append(lstf, f)
		}
	}()
	var pt = int32(1000) // 指令发送保护时间
	var pb2data = &msgopen.MsgGBOpen{}
	err := pb2data.Unmarshal(*b)
	if err != nil {
		panic(err.Error())
	}
	getprotocol := false
	if pb2data.DataID.Area == "0000" && dp.AreaCode != "" {
		pb2data.DataID.Area = dp.AreaCode
	}
	var cmd = fmt.Sprintf("%02x%02x", pb2data.DataID.Fun, pb2data.DataID.Afn)
	var d bytes.Buffer
	switch cmd {
	case "0a04": // 设置参数,可多数据单元下发
		d.Reset()
		for _, v := range pb2data.DataID.UintID {
			d.Write(setPnFn(v.Pn))
			d.Write(setPnFn(v.Fn))
			switch v.Pn {
			case 0:
				switch v.Fn {
				case 1: // 终端上行通信口通信参数设置
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(pb2data.Afn04P0F1.Rts))
					d.WriteByte(byte(pb2data.Afn04P0F1.MasterRts))		
					s1 := fmt.Sprintf("00%02b%012b",pb2data.Afn04P0F1.ResendTimeout,pb2data.Afn04P0F1.ResendNum)
					d.Write([]byte{gopsu.String2Int8(s1[8:], 2), gopsu.String2Int8(s1[:8], 2)})
					rs := []string{"0", "0", "0", "0", "0", "0", "0", "0" }
					for k , rm := range pb2data.Afn04P0F1.ReportMark {
						if rm != 0 {
							rs[k] = "1"
						}
					}
					s2 := gopsu.ReverseString(strings.Join(rs, ""))
					d.WriteByte(gopsu.String2Int8(s2, 2))
					d.WriteByte(byte(pb2data.Afn04P0F1.KeepAlive))						

				case 3: // 主站IP地址和端口
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))	
					// 主IP
					ip1 := strings.Split(pb2data.Afn04P0F3.MainIp, ".")
					if len(ip1) == 4{
						d.WriteByte(1)
					}else {
						d.WriteByte(2)
					}
					for _, v := range ip1 {
						d.WriteByte(gopsu.String2Int8(v, 10))
					}
					// 主端口
					d.Write([]byte{byte(pb2data.Afn04P0F3.MainPort % 256), byte(pb2data.Afn04P0F3.MainPort / 256)})
					// 备用IP
					ip2 := strings.Split(pb2data.Afn04P0F3.BackupIp, ".")
					if len(ip2) == 4{
						d.WriteByte(1)
					}else {
						d.WriteByte(2)
					}
					for _, v := range ip2 {
						d.WriteByte(gopsu.String2Int8(v, 10))
					}
					// 备用端口
					d.Write([]byte{byte(pb2data.Afn04P0F3.BackupPort % 256), byte(pb2data.Afn04P0F3.BackupPort / 256)})
					
					// APN
					for i := 0; i < 16; i++ {
						if i < len(pb2data.Afn04P0F3.Apn) {
							d.WriteByte(pb2data.Afn04P0F3.Apn[i])
						} else {
							d.WriteByte(0)
						}
					}
					// 用户名
					for i := 0; i < 32; i++ {
						if i < len(pb2data.Afn04P0F3.User) {
							d.WriteByte(pb2data.Afn04P0F3.User[i])
						} else {
							d.WriteByte(0)
						}
					}
					// 密码
					for i := 0; i < 32; i++ {
						if i < len(pb2data.Afn04P0F3.Pwd) {
							d.WriteByte(pb2data.Afn04P0F3.Pwd[i])
						} else {
							d.WriteByte(0)
						}
					}

				case 9: // 终端事件记录配置设置
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))	
				
					ea := []string{}
					er := []string{}
					for i :=0 ;i<64;i++{
						if i < len(pb2data.Afn04P0F9.EventsAvailable){
							ea = append(ea,string(pb2data.Afn04P0F9.EventsReport[i]))
						} else{
							ea = append(ea,"0")
						}
						if i < len(pb2data.Afn04P0F9.EventsReport){
							er = append(er,string(pb2data.Afn04P0F9.EventsReport[i]))
						} else{
							er = append(er,"0")
						}
					}
					s1 := gopsu.ReverseString(strings.Join(ea, ""))
					s2 := gopsu.ReverseString(strings.Join(er, ""))
					
					d.Write([]byte{gopsu.String2Int8(s1[56:], 2), gopsu.String2Int8(s1[48:56], 2), 
						gopsu.String2Int8(s1[40:48], 2), gopsu.String2Int8(s1[32:40], 2),
						gopsu.String2Int8(s1[24:32], 2), gopsu.String2Int8(s1[16:24], 2),
						gopsu.String2Int8(s1[8:16], 2), gopsu.String2Int8(s1[:8], 2)})						
					d.Write([]byte{gopsu.String2Int8(s2[56:], 2), gopsu.String2Int8(s2[48:56], 2), 
						gopsu.String2Int8(s2[40:48], 2), gopsu.String2Int8(s2[32:40], 2),
						gopsu.String2Int8(s2[24:32], 2), gopsu.String2Int8(s2[16:24], 2),
						gopsu.String2Int8(s2[8:16], 2), gopsu.String2Int8(s2[:8], 2)})

				case 10: // 设备状态输入参数
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))	

					sa := []string{}
					sh := []string{}
					for i :=0 ;i<32;i++{
						if i < len(pb2data.Afn04P0F10.SwitchinAvailable){
							sa = append(sa,string(pb2data.Afn04P0F10.SwitchinAvailable[i]))
						} else{
							sa = append(sa,"0")
						}
						if i < len(pb2data.Afn04P0F10.SwitchinHopping){
							sh = append(sh,string(pb2data.Afn04P0F10.SwitchinAvailable[i]))
						} else{
							sh = append(sh,"0")
						}
					}
					s1 := gopsu.ReverseString(strings.Join(sa, ""))
					s2 := gopsu.ReverseString(strings.Join(sh, ""))
					
					d.Write([]byte{gopsu.String2Int8(s1[24:32], 2), gopsu.String2Int8(s1[16:24], 2),
						gopsu.String2Int8(s1[8:16], 2), gopsu.String2Int8(s1[:8], 2)})						
					d.Write([]byte{gopsu.String2Int8(s2[24:32], 2), gopsu.String2Int8(s2[16:24], 2),
						gopsu.String2Int8(s2[8:16], 2), gopsu.String2Int8(s2[:8], 2)})

				case 11: // GPS地理位置信息
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					// 经度
					d.WriteByte(byte(pb2data.Afn04P0F11.LongitudeMark))	
					du,fen,miao:=gopsu.GPS2DFM(pb2data.Afn04P0F11.Longitude)	
					d.Write([]byte{byte(du),byte(fen),byte(int(miao*100)%256),byte(int(miao*100)/256)})
					// 纬度
					d.WriteByte(byte(pb2data.Afn04P0F11.LatitudeMark))		
					du,fen,miao=gopsu.GPS2DFM(pb2data.Afn04P0F11.Latitude)
					d.Write([]byte{byte(du),byte(fen),byte(int(miao*100)%256),byte(int(miao*100)/256)})

				case 41: // 开关量输出参数关联
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))	
					d.WriteByte(byte(len(pb2data.Afn04P0F41.SwitchoutLoops)))
					for _,v := range pb2data.Afn04P0F41.SwitchoutLoops{
						d.WriteByte(byte(v))
					}

				case 42: // 模拟量采集参数关联
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))	
					d.WriteByte(byte(pb2data.Afn04P0F42.VoltageTransformer))
					d.WriteByte(byte(pb2data.Afn04P0F42.EnergyATransformer))
					d.WriteByte(byte(pb2data.Afn04P0F42.EnergyBTransformer))
					d.WriteByte(byte(pb2data.Afn04P0F42.EnergyCTransformer))
					d.WriteByte(byte(len(pb2data.Afn04P0F42.CurrentSetting)))
					for _,v := range pb2data.Afn04P0F42.CurrentSetting{
						d.WriteByte(byte(v.Transformer))
						d.WriteByte(byte(v.Phase))
					}

				case 46: // 周回路控制表
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))	
					// 周日设置
					for _,v := range pb2data.Afn04P0F46.WeekDay7{
						d.Write(gopsu.STime2Bcd(v.TimeOn))
						d.Write(gopsu.STime2Bcd(v.TimeOff))
					}
					// 周一~周六设置
					for _,v := range pb2data.Afn04P0F46.WeekDay1{
						d.Write(gopsu.STime2Bcd(v.TimeOn))
						d.Write(gopsu.STime2Bcd(v.TimeOff))
					}
					for _,v := range pb2data.Afn04P0F46.WeekDay2{
						d.Write(gopsu.STime2Bcd(v.TimeOn))
						d.Write(gopsu.STime2Bcd(v.TimeOff))
					}
					for _,v := range pb2data.Afn04P0F46.WeekDay3{
						d.Write(gopsu.STime2Bcd(v.TimeOn))
						d.Write(gopsu.STime2Bcd(v.TimeOff))
					}
					for _,v := range pb2data.Afn04P0F46.WeekDay4{
						d.Write(gopsu.STime2Bcd(v.TimeOn))
						d.Write(gopsu.STime2Bcd(v.TimeOff))
					}
					for _,v := range pb2data.Afn04P0F46.WeekDay5{
						d.Write(gopsu.STime2Bcd(v.TimeOn))
						d.Write(gopsu.STime2Bcd(v.TimeOff))
					}
					for _,v := range pb2data.Afn04P0F46.WeekDay6{
						d.Write(gopsu.STime2Bcd(v.TimeOn))
						d.Write(gopsu.STime2Bcd(v.TimeOff))
					}

				case 49: // 经纬度开关灯偏移
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))						
					d.WriteByte(gopsu.SignedInt322Byte(pb2data.Afn04P0F49.OffsetOn))
					d.WriteByte(gopsu.SignedInt322Byte(pb2data.Afn04P0F49.OffsetOff))
				
				case 50: // 设定全数据上送周期
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(pb2data.Afn04P0F50.ReportTimer))
				
				case 51: // 设置模拟量上下限【暂未确定】
				case 52: // 设置漏电保护参数
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))	
					d.WriteByte(byte(pb2data.Afn04P0F52.LoopNo))
					d.WriteByte(byte(pb2data.Afn04P0F52.LoopEnable))
					d.WriteByte(byte(pb2data.Afn04P0F52.LoopSwitchout))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F52.Level1Limit)/1000,"%07.03f"))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F52.Level2Limit)/1000,"%07.03f"))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F52.Level3Limit)/1000,"%07.03f"))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F52.Level4Limit)/1000,"%07.03f"))

				case 53: // 设置光照度限值参数
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F53.LuxThreshold),"%04.0f"))
					//d.Write([]byte{byte(pb2data.Afn04P0F53.LuxThreshold%256),byte(pb2data.Afn04P0F53.LuxThreshold/256)})
					d.WriteByte(byte(pb2data.Afn04P0F53.TimeTick))
				
				case 57: // 停运/投运
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(pb2data.Afn04P0F57.RuntimeMark))
					lm := []string{}
					for i :=0 ;i<48;i++{
						if i < len(pb2data.Afn04P0F57.LoopMark){
							lm = append(lm,string(pb2data.Afn04P0F57.LoopMark[i]))
						} else{
							lm = append(lm,"0")
						}
					}
					s := gopsu.ReverseString(strings.Join(lm, ""))
					
					d.Write([]byte{gopsu.String2Int8(s[40:], 2), gopsu.String2Int8(s[32:40], 2),
						gopsu.String2Int8(s[24:32], 2), gopsu.String2Int8(s[16:24], 2),
						gopsu.String2Int8(s[8:16], 2), gopsu.String2Int8(s[:8], 2)})				
				}
			default:
				switch v.Fn {				
				case 14: // 扩展设备配置参数（外接设备配置）【暂未确定】
				case 15: // 继电器输出控制方案
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))

					for k , pnf := range pb2data.Afn04PnF15{
						// 起始日期 持续时间
						d.Write(gopsu.Float642BcdBytes(gopsu.String2Float64(pnf.DtStart), "%6.0f"))
						d.WriteByte(byte(pnf.DtDays))
						// 继电器序号选择标志位
						sn:=[]string{}
						for i :=0 ;i<16;i++{
							if i < len(pnf.SwitchoutNo){
								sn = append(sn,string(pnf.SwitchoutNo[i]))
							} else{
								sn = append(sn,"0")
							}
						}
						s := gopsu.ReverseString(strings.Join(sn, ""))
						d.Write([]byte{gopsu.String2Int8(s[8:], 2), gopsu.String2Int8(s[:8], 2)})	
						// 输出时段数
						d.WriteByte(byte(len(pnf.TimeSlot)))
						// 控制时段
						for _,v := range pnf.TimeSlot{
							d.Write(gopsu.STime2Bcd(v.TimeOn))
							d.Write(gopsu.STime2Bcd(v.TimeOff))
						}
					}
				}
			}
		}
		if d.Len() > 0 {
			f := &Fwd{
				DataDst: fmt.Sprintf("wlst-open-%d-%s", pb2data.DataID.Addr, pb2data.DataID.Area),
				DataMsg: dp.BuildCommand(d.Bytes(), pb2data.DataID.Addr, 1, pb2data.DataID.Fun, 0, 1, pb2data.DataID.Afn, 1, pb2data.DataID.Seq, pb2data.DataID.Area),
				Src:     fmt.Sprintf("%v", pb2data),
				DataSP:  byte(pb2data.DataID.Sp),
				DataPT:  pt,
			}
			lstf = append(lstf, f)
			getprotocol = true
		}
	default: // 其他命令，仅单数据单元下发
		for _, v := range pb2data.DataID.UintID {
			d.Reset()
			switch cmd {
			case "0101": // 复位
				switch v.Pn {
				case 0:
					switch v.Fn {
					case 1, 2, 3, 4: // 硬件初始化(重启)/数据区初始化(预留)/参数及全体数据区初始化(即恢复至出厂配置)/参数(除与系统主站通信有关的)及全体数据区初始化
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
					}
				}
			case "0a05": // 控制命令
				switch v.Pn {
				case 0:
					switch v.Fn {
					case 29, 37: // 允许/禁止主动上报
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
					case 1: // 允许合闸/跳闸
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
						sout := []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
						sdo := []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
						var donow = true
						for _, sc := range pb2data.Afn05P0F1.SwitchoutCtrl {
							sout[sc.SwitchoutNo-1] = "1"
							sdo[sc.SwitchoutNo-1] = fmt.Sprintf("%d", sc.SwitchoutDo)
							if sc.SwitchoutTime > 0 {
								donow = false
							}
						}
						s := gopsu.ReverseString(strings.Join(sout, ""))
						d.Write([]byte{gopsu.String2Int8(s[8:], 2), gopsu.String2Int8(s[:8], 2)})
						s = gopsu.ReverseString(strings.Join(sdo, ""))
						d.Write([]byte{gopsu.String2Int8(s[8:], 2), gopsu.String2Int8(s[:8], 2)})
						switch dp.AreaCode {
						case "4201": // 武汉
							if donow {
								d.Write([]byte{0, 0, 0, 0, 0, 0})
							} else {
								for _, sc := range pb2data.Afn05P0F1.SwitchoutCtrl {
									d.Write(gopsu.Stamp2BcdDT(sc.SwitchoutTime))
								}
							}
						default:
							for _, sc := range pb2data.Afn05P0F1.SwitchoutCtrl {
								d.Write(gopsu.Stamp2BcdDT(sc.SwitchoutTime))
							}
						}
						// 设置额外指令保护时间
						// TODO:
					case 9: // 消除漏电分闸/报警
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
						d.WriteByte(byte(len(pb2data.Afn05P0F9.LoopMark)))
						for _, v := range pb2data.Afn05P0F9.LoopMark {
							d.WriteByte(byte(v))
						}
					case 31: // 对时命令
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
						d.Write(gopsu.Stamp2BcdDT(pb2data.Afn05P0F31.TimeUnix))
					}
				}
			case "0b03": // 中继站命令（未支持）
			case "0b06": // 身份认证以及密钥协商（未支持）
			case "0b08": // 请求被级联终端主动上报（未支持）
			case "0b09": // 请求终端配置
				switch v.Pn {
				case 0:
					switch v.Fn {
					case 1: // 终端版本信息
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
					}
				}
			case "0b0a": // 查询参数
				switch v.Pn {
				case 0:
					switch v.Fn {
					case 1, 3, 9, 10, 11, 14, 15, 41, 42, 46, 49, 50, 51, 52, 53, 57: // 终端上行通信口通信参数设置
						// 主站 IP 地址  和端口
						// 终端事件记录配置设置
						// 设备状态输入参数
						// GPS 地理位置信息
						// 扩展设备配置参数
						// 开关量输出参数关联
						// 模拟量采集参数关联
						// 周回路控制表
						// 经纬度开关灯偏移
						// 查询全数据上送周期
						// 查询模拟量上下限
						// 查询漏电保护参数
						// 查询光照度限值 参数
						// 停运/投运
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
					}
				}
			case "0b0b": // 请求任务数据（未支持）
			case "0b0c": // 请求实时数据
				switch v.Pn {
				case 0:
					switch v.Fn {
					case 2, 3, 4, 6, 7, 99, 18, 19, 20: // 终端日历时钟
						// 进线模拟量数据(全数据)(报警主报)
						// 终端上行通信状态
						// 终端当前控制状态
						// 终端事件计数器当前值
						// 终端状态量及变位标志(全数据)
						// 终端回路事件报警状态(全数据)
						// 漏电检测数据(全数据)
						// 光照度数据(主报)
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
					}
				case 0xffff: // 出线模拟量数据(全数据)(报警主报)
					switch v.Fn {
					case 1:
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
					}
				}
			case "0b0d": // 请求历史数据
				switch v.Pn {
				case 0:
					switch v.Fn {
					case 2: // 模拟量历史数据曲线(进线)
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
						d.Write(gopsu.Stamp2BcdDT(pb2data.Afn0DP0F2.DtStart)[1:])
						d.WriteByte(byte(pb2data.Afn0DP0F2.DataDensity))
						d.WriteByte(byte(pb2data.Afn0DP0F2.DataNum))
						d.WriteByte(0)
					}
				default:
					switch v.Fn {
					case 1: // 模拟量历史数据曲线(出线)
						// 循环分解为多条指令
						for _, vv := range pb2data.Afn0DPnF1.LoopNo {
							d.Write(setPnFn(vv))
							d.Write(setPnFn(v.Fn))
							d.Write(gopsu.Stamp2BcdDT(pb2data.Afn0DPnF1.DtStart)[1:])
							d.WriteByte(byte(pb2data.Afn0DPnF1.DataDensity))
							d.WriteByte(byte(pb2data.Afn0DPnF1.DataNum))
							d.WriteByte(byte(vv))
							f := &Fwd{
								DataDst: fmt.Sprintf("wlst-open-%d-%s", pb2data.DataID.Addr, pb2data.DataID.Area),
								DataMsg: dp.BuildCommand(d.Bytes(), pb2data.DataID.Addr, 1, pb2data.DataID.Fun, 0, 1, pb2data.DataID.Afn, 1, pb2data.DataID.Seq, pb2data.DataID.Area),
								Src:     fmt.Sprintf("%v", pb2data),
							}
							lstf = append(lstf, f)
							d.Reset()
						}
					case 3: // 漏电历史数据曲线
						// 循环分解为多条指令
						for _, vv := range pb2data.Afn0DPnF3.LoopNo {
							d.Write(setPnFn(vv))
							d.Write(setPnFn(v.Fn))
							d.Write(gopsu.Stamp2BcdDT(pb2data.Afn0DPnF3.DtStart)[1:])
							d.WriteByte(byte(pb2data.Afn0DPnF3.DataDensity))
							d.WriteByte(byte(pb2data.Afn0DPnF3.DataNum))
							d.WriteByte(byte(vv))
							f := &Fwd{
								DataDst: fmt.Sprintf("wlst-open-%d-%s", pb2data.DataID.Addr, pb2data.DataID.Area),
								DataMsg: dp.BuildCommand(d.Bytes(), pb2data.DataID.Addr, 1, pb2data.DataID.Fun, 0, 1, pb2data.DataID.Afn, 1, pb2data.DataID.Seq, pb2data.DataID.Area),
								Src:     fmt.Sprintf("%v", pb2data),
							}
							lstf = append(lstf, f)
							d.Reset()
						}
					}
				}
			case "0b0e": // 请求事件数据
				switch v.Pn {
				case 0:
					switch v.Fn {
					case 1, 2: // 查询重要事件/查询一般事件
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
						d.WriteByte(byte(pb2data.Afn0EP0F1.Pm))
						d.WriteByte(byte(pb2data.Afn0EP0F1.Pn))
					}
				}
			case "0b0f": // 文件传输（未支持）
			case "0b10": // 数据转发
				switch v.Pn {
				case 0:
					switch v.Fn {
					case 1: // 485转发
					case 9: // ftp升级
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
						// ftp-ip/port
						ip := strings.Split(gopsu.IPInt642String(pb2data.Afn10P0F9.FtpIp), ".")
						for _, v := range ip {
							d.WriteByte(gopsu.String2Int8(v, 10))
						}
						d.Write([]byte{byte(pb2data.Afn10P0F9.FtpPort % 256), byte(pb2data.Afn10P0F9.FtpPort / 256)})
						// 备用ftp参数为空
						d.Write([]byte{0, 0, 0, 0, 0, 0})
						// 用户名
						for i := 0; i < 10; i++ {
							if i < len(pb2data.Afn10P0F9.FtpUser) {
								d.WriteByte(pb2data.Afn10P0F9.FtpUser[i])
							} else {
								d.WriteByte(0)
							}
						}
						// 密码
						for i := 0; i < 10; i++ {
							if i < len(pb2data.Afn10P0F9.FtpPwd) {
								d.WriteByte(pb2data.Afn10P0F9.FtpPwd[i])
							} else {
								d.WriteByte(0)
							}
						}
						// 服务器路径+备用路径
						for i := 0; i < 40; i++ {
							if i < len(pb2data.Afn10P0F9.FtpDir) {
								d.WriteByte(pb2data.Afn10P0F9.FtpDir[i])
							} else {
								d.WriteByte(0)
							}
						}
						// 文件名(5个)
						for i := 0; i < 50; i++ {
							if i < len(pb2data.Afn10P0F9.FtpFile) {
								d.WriteByte(pb2data.Afn10P0F9.FtpFile[i])
							} else {
								d.WriteByte(0)
							}
						}
					}
				}
			}
			if d.Len() > 0 {
				f := &Fwd{
					DataDst: fmt.Sprintf("wlst-open-%d-%s", pb2data.DataID.Addr, pb2data.DataID.Area),
					DataMsg: dp.BuildCommand(d.Bytes(), pb2data.DataID.Addr, 1, pb2data.DataID.Fun, 0, 1, pb2data.DataID.Afn, 1, pb2data.DataID.Seq, pb2data.DataID.Area),
					Src:     fmt.Sprintf("%v", pb2data),
					DataSP:  byte(pb2data.DataID.Sp),
					DataPT:  pt,
				}
				lstf = append(lstf, f)
				getprotocol = true
			}
		}
	}
	if !getprotocol {
		f := &Fwd{
			// DataCmd: cmd,
			Src: fmt.Sprintf("%v", pb2data),
			Ex:  "unknow protocol",
			// DstType: byte(pb2data.Head.Src),
		}
		lstf = append(lstf, f)
	}
	return lstf
}
