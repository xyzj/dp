package v6

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/xyzj/gopsu"
	msgopen "github.com/xyzj/proto/msgwlst"
)

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
			// d.Write(setPnFn(v.Pn))
			// d.Write(setPnFn(v.Fn))
			switch v.Pn {
			case 0:
				switch v.Fn {
				case 1: // 终端上行通信口通信参数设置
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(pb2data.Afn04P0F1.Rts))
					d.WriteByte(byte(pb2data.Afn04P0F1.MasterRts))
					s1 := fmt.Sprintf("00%02b%012b", pb2data.Afn04P0F1.ResendTimeout, pb2data.Afn04P0F1.ResendNum)
					d.Write([]byte{gopsu.String2Int8(s1[8:], 2), gopsu.String2Int8(s1[:8], 2)})
					rs := []string{"0", "0", "0", "0", "0", "0", "0", "0"}
					for k, rm := range pb2data.Afn04P0F1.ReportMark {
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
					if len(ip1) == 4 {
						d.WriteByte(1)
					} else {
						d.WriteByte(2)
					}
					for _, v := range ip1 {
						d.WriteByte(gopsu.String2Int8(v, 10))
					}
					// 主端口
					d.Write([]byte{byte(pb2data.Afn04P0F3.MainPort % 256), byte(pb2data.Afn04P0F3.MainPort / 256)})
					// 备用IP
					ip2 := strings.Split(pb2data.Afn04P0F3.BackupIp, ".")
					if len(ip2) == 4 {
						d.WriteByte(1)
					} else {
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

					ea := make([]string, 64)
					er := make([]string, 64)
					for i := 0; i < 64; i++ {
						ea[i] = "0"
						er[i] = "0"
					}
					for _, v := range pb2data.Afn04P0F9.EventsAvailable {
						ea[v] = "1"
					}
					for _, v := range pb2data.Afn04P0F9.EventsReport {
						er[v] = "1"
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
					for i := 0; i < 32; i++ {
						if i < len(pb2data.Afn04P0F10.SwitchinAvailable) {
							sa = append(sa, fmt.Sprintf("%d", pb2data.Afn04P0F10.SwitchinAvailable[i]))
						} else {
							sa = append(sa, "0")
						}
						if i < len(pb2data.Afn04P0F10.SwitchinHopping) {
							sh = append(sh, fmt.Sprintf("%d", pb2data.Afn04P0F10.SwitchinHopping[i]))
						} else {
							sh = append(sh, "0")
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
					du, fen, miao := gopsu.GPS2DFM(pb2data.Afn04P0F11.Longitude)
					d.Write([]byte{byte(du), byte(fen), byte(int(miao*100) % 256), byte(int(miao*100) / 256)})
					// 纬度
					d.WriteByte(byte(pb2data.Afn04P0F11.LatitudeMark))
					du, fen, miao = gopsu.GPS2DFM(pb2data.Afn04P0F11.Latitude)
					d.Write([]byte{byte(du), byte(fen), byte(int(miao*100) % 256), byte(int(miao*100) / 256)})

				case 41: // 开关量输出参数关联
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(len(pb2data.Afn04P0F41.SwitchoutLoops)))
					for _, v := range pb2data.Afn04P0F41.SwitchoutLoops {
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
					for _, v := range pb2data.Afn04P0F42.CurrentSetting {
						d.WriteByte(byte(v.Transformer))
						d.WriteByte(byte(v.Phase))
					}

				case 46: // 周回路控制表
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					// 周日设置
					for _, v := range pb2data.Afn04P0F46.WeekDay7 {
						d.Write(gopsu.STime2Bcd(v.TimeOn))
						d.Write(gopsu.STime2Bcd(v.TimeOff))
					}
					// 周一~周六设置
					for _, v := range pb2data.Afn04P0F46.WeekDay1 {
						d.Write(gopsu.STime2Bcd(v.TimeOn))
						d.Write(gopsu.STime2Bcd(v.TimeOff))
					}
					for _, v := range pb2data.Afn04P0F46.WeekDay2 {
						d.Write(gopsu.STime2Bcd(v.TimeOn))
						d.Write(gopsu.STime2Bcd(v.TimeOff))
					}
					for _, v := range pb2data.Afn04P0F46.WeekDay3 {
						d.Write(gopsu.STime2Bcd(v.TimeOn))
						d.Write(gopsu.STime2Bcd(v.TimeOff))
					}
					for _, v := range pb2data.Afn04P0F46.WeekDay4 {
						d.Write(gopsu.STime2Bcd(v.TimeOn))
						d.Write(gopsu.STime2Bcd(v.TimeOff))
					}
					for _, v := range pb2data.Afn04P0F46.WeekDay5 {
						d.Write(gopsu.STime2Bcd(v.TimeOn))
						d.Write(gopsu.STime2Bcd(v.TimeOff))
					}
					for _, v := range pb2data.Afn04P0F46.WeekDay6 {
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

				case 51: // 设置模拟量上下限
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					// 电压上下限
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F51.VoltageLowerLimit)/10, "%03.01f"))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F51.VoltageUpperLimit)/10, "%03.01f"))
					// 电流回路数
					d.WriteByte(byte(len(pb2data.Afn04P0F51.CurrentSetting)))
					for _, cs := range pb2data.Afn04P0F51.CurrentSetting {
						// 电流有效时段数
						d.WriteByte(byte(len(cs.LoopSetting)))
						for _, ls := range cs.LoopSetting {
							d.Write(gopsu.STime2Bcd(ls.TimeStart))
							d.Write(gopsu.STime2Bcd(ls.TimeEnd))
							d.Write(gopsu.Float642BcdBytes(float64(ls.CurrentLowerLimit), "%07.03f"))
							d.Write(gopsu.Float642BcdBytes(float64(ls.CurrentUpperLimit), "%07.03f"))
						}
					}

				case 52: // 设置漏电保护参数
					for i := 0; i < 8; i++ {
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
						d.WriteByte(byte(i))
						d.WriteByte(byte(pb2data.Afn04P0F52.LeakageLimit[i].LoopEnable))
						d.WriteByte(byte(pb2data.Afn04P0F52.LeakageLimit[i].LoopSwitchout))
						d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F52.LeakageLimit[i].Level1Limit)/1000, "%07.03f"))
						d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F52.LeakageLimit[i].Level2Limit)/1000, "%07.03f"))
						d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F52.LeakageLimit[i].Level3Limit)/1000, "%07.03f"))
						d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F52.LeakageLimit[i].Level4Limit)/1000, "%07.03f"))
					}

				case 53: // 设置光照度限值参数
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F53.LuxThreshold), "%04.0f"))
					//d.Write([]byte{byte(pb2data.Afn04P0F53.LuxThreshold%256),byte(pb2data.Afn04P0F53.LuxThreshold/256)})
					d.WriteByte(byte(pb2data.Afn04P0F53.TimeTick))

				case 57: // 停运/投运
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(pb2data.Afn04P0F57.RuntimeMark))
					lm := []string{}
					for i := 0; i < 48; i++ {
						if i < len(pb2data.Afn04P0F57.LoopMark) {
							lm = append(lm, string(pb2data.Afn04P0F57.LoopMark[i]))
						} else {
							lm = append(lm, "0")
						}
					}
					s := gopsu.ReverseString(strings.Join(lm, ""))

					d.Write([]byte{gopsu.String2Int8(s[40:], 2), gopsu.String2Int8(s[32:40], 2),
						gopsu.String2Int8(s[24:32], 2), gopsu.String2Int8(s[16:24], 2),
						gopsu.String2Int8(s[8:16], 2), gopsu.String2Int8(s[:8], 2)})
				case 65: // 电流回路矢量
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(len(pb2data.Afn04P0F65.SwitchinVector)))
					for _, v := range pb2data.Afn04P0F65.SwitchinVector {
						d.WriteByte(byte(v))
					}
				case 66: // 电流回路遥信矢量
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(len(pb2data.Afn04P0F66.SwitchinSwitchout)))
					for _, v := range pb2data.Afn04P0F66.SwitchinSwitchout {
						d.WriteByte(byte(v))
					}
				case 67: // 开关量输出矢量
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(len(pb2data.Afn04P0F67.SwitchoutVector)))
					for _, v := range pb2data.Afn04P0F67.SwitchoutVector {
						d.WriteByte(byte(v))
					}
				case 68: // 设置断电保护参数
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					// 是否启用欠压断电
					if pb2data.Afn04P0F68.VoltageLowerLimit < 100 {
						d.Write([]byte{0, 0, 0})
					} else {
						d.WriteByte(byte(pb2data.Afn04P0F68.VoltageLowerBreak))
						d.WriteByte(byte(pb2data.Afn04P0F68.VoltageLowerBreak))
						d.WriteByte(byte(pb2data.Afn04P0F68.VoltageLowerBreak))
					}
					// 电压下限
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F68.VoltageLowerLimit)/10, "%03.01f"))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F68.VoltageLowerLimit)/10, "%03.01f"))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F68.VoltageLowerLimit)/10, "%03.01f"))
					// 是否启用过压断电
					if pb2data.Afn04P0F68.VoltageLowerLimit > 300 {
						d.Write([]byte{0, 0, 0})
					} else {
						d.WriteByte(byte(pb2data.Afn04P0F68.VoltageUpperBreak))
						d.WriteByte(byte(pb2data.Afn04P0F68.VoltageUpperBreak))
						d.WriteByte(byte(pb2data.Afn04P0F68.VoltageUpperBreak))
					}
					// 电压上限
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F68.VoltageUpperLimit)/10, "%03.01f"))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F68.VoltageUpperLimit)/10, "%03.01f"))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F68.VoltageUpperLimit)/10, "%03.01f"))
				}
			default:
				switch v.Fn {
				case 14: // 扩展设备配置参数（外接设备配置）【暂未确定】
				case 15: // 继电器输出控制方案
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					for _, pnf := range pb2data.Afn04PnF15 {
						// 起始日期 持续时间
						d.Write(gopsu.Float642BcdBytes(gopsu.String2Float64(pnf.DtStart), "%6.0f"))
						d.WriteByte(byte(pnf.DtDays))
						// 继电器序号选择标志位
						sn := []string{}
						for i := 0; i < 16; i++ {
							if i < len(pnf.SwitchoutNo) {
								sn = append(sn, string(pnf.SwitchoutNo[i]))
							} else {
								sn = append(sn, "0")
							}
						}
						s := gopsu.ReverseString(strings.Join(sn, ""))
						d.Write([]byte{gopsu.String2Int8(s[8:], 2), gopsu.String2Int8(s[:8], 2)})
						// 输出时段数
						d.WriteByte(byte(len(pnf.TimeSlot)))
						// 控制时段
						for _, v := range pnf.TimeSlot {
							d.Write(gopsu.STime2Bcd(v.TimeOn))
							d.Write(gopsu.STime2Bcd(v.TimeOff))
						}
					}
				}
			}
		}
		if d.Len() > 0 {
			f := &Fwd{
				DataDst: fmt.Sprintf("gb-open-%d-%s", pb2data.DataID.Addr, pb2data.DataID.Area),
				DataMsg: dp.BuildCommand(d.Bytes(), pb2data.DataID.Addr, 1, pb2data.DataID.Fun, 0, 1, pb2data.DataID.Afn, 1, pb2data.DataID.Seq, pb2data.DataID.Area),
				Src:     fmt.Sprintf("%v", pb2data),
				DataSP:  byte(pb2data.DataID.Sp),
				DataPT:  pt,
			}
			lstf = append(lstf, f)
			getprotocol = true
		}
	case "0a05": // 控制命令
		d.Reset()
		for _, v := range pb2data.DataID.UintID {
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
		}
		if d.Len() > 0 {
			f := &Fwd{
				DataDst: fmt.Sprintf("gb-open-%d-%s", pb2data.DataID.Addr, pb2data.DataID.Area),
				DataMsg: dp.BuildCommand(d.Bytes(), pb2data.DataID.Addr, 1, pb2data.DataID.Fun, 0, 1, pb2data.DataID.Afn, 1, pb2data.DataID.Seq, pb2data.DataID.Area),
				Src:     fmt.Sprintf("%v", pb2data),
				DataSP:  byte(pb2data.DataID.Sp),
				DataPT:  pt,
			}
			lstf = append(lstf, f)
			getprotocol = true
		}
	case "0b0c": // 请求实时数据
		d.Reset()
		for _, v := range pb2data.DataID.UintID {
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
		}
		if d.Len() > 0 {
			f := &Fwd{
				DataDst: fmt.Sprintf("gb-open-%d-%s", pb2data.DataID.Addr, pb2data.DataID.Area),
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
								DataDst: fmt.Sprintf("gb-open-%d-%s", pb2data.DataID.Addr, pb2data.DataID.Area),
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
								DataDst: fmt.Sprintf("gb-open-%d-%s", pb2data.DataID.Addr, pb2data.DataID.Area),
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
					case 2: // 透明转发
						d.Write(setPnFn(v.Pn))
						d.Write(setPnFn(v.Fn))
						// 串口配置
						d.WriteByte(byte(pb2data.Afn10P0F2.RsSetting.Idx))
						d.WriteByte(byte(pb2data.Afn10P0F2.RsSetting.Bps))
						d.WriteByte(byte(pb2data.Afn10P0F2.RsSetting.Rc))
						// 透传数据拼装
						var da bytes.Buffer
						switch pb2data.Afn10P0F2.Cmd {
						case "wlst.mru.1100":
							da.WriteByte(0x68)
							da.Write(gopsu.Float642BcdBytesBigOrder(float64(pb2data.Afn10P0F2.WlstMru_9100.Addr), "%12.0f"))

							da.WriteByte(0x68)
							if pb2data.Afn10P0F2.WlstMru_9100.Ver == 2 { // 2007
								da.WriteByte(0x11)
								da.WriteByte(0x4)
								switch pb2data.Afn10P0F2.WlstMru_9100.MeterReadingType {
								case 1:
									da.WriteByte(byte(pb2data.Afn10P0F2.WlstMru_9100.MeterReadingDate + 0x33))
									da.WriteByte(0x00 + 0x33)
									da.WriteByte(0x15 + 0x33)
									da.WriteByte(0x00 + 0x33)
								case 2:
									da.WriteByte(byte(pb2data.Afn10P0F2.WlstMru_9100.MeterReadingDate + 0x33))
									da.WriteByte(0x00 + 0x33)
									da.WriteByte(0x29 + 0x33)
									da.WriteByte(0x00 + 0x33)
								case 3:
									da.WriteByte(byte(pb2data.Afn10P0F2.WlstMru_9100.MeterReadingDate + 0x33))
									da.WriteByte(0x00 + 0x33)
									da.WriteByte(0x3d + 0x33)
									da.WriteByte(0x00 + 0x33)
								case 4:
									da.WriteByte(byte(pb2data.Afn10P0F2.WlstMru_9100.MeterReadingDate + 0x33))
									da.WriteByte(0x00 + 0x33)
									da.WriteByte(0x01 + 0x33)
									da.WriteByte(0x00 + 0x33)
								case 5:
									da.WriteByte(byte(pb2data.Afn10P0F2.WlstMru_9100.MeterReadingDate + 0x33))
									da.WriteByte(0x00 + 0x33)
									da.WriteByte(0x00 + 0x33)
									da.WriteByte(0x00 + 0x33)
								default:
									da.WriteByte(byte(pb2data.Afn10P0F2.WlstMru_9100.MeterReadingDate + 0x33))
									da.WriteByte(0x00 + 0x33)
									da.WriteByte(0x00 + 0x33)
									da.WriteByte(0x00 + 0x33)
								}
							} else { // 1997
								da.WriteByte(0x1)
								da.WriteByte(0x2)
								switch pb2data.Afn10P0F2.WlstMru_9100.MeterReadingType {
								case 1: // d0=00110000
									da.WriteByte(0x34)
									da.WriteByte(0x17)
								case 2: // D0=01010000
									da.WriteByte(0x35)
									da.WriteByte(0x17)
								case 3: // D0=01100000
									da.WriteByte(0x36)
									da.WriteByte(0x17)
								case 4: // D0=00010000
									da.WriteByte(gopsu.String2Int8("00010000", 2) + 0x33)
									da.WriteByte(gopsu.String2Int8(fmt.Sprintf("1001%02b00", pb2data.Afn10P0F2.WlstMru_9100.MeterReadingDate), 2) + 0x33)
								case 5: // D0=00010000
									da.WriteByte(gopsu.String2Int8("00000000", 2) + 0x33)
									da.WriteByte(gopsu.String2Int8(fmt.Sprintf("1001%02b00", pb2data.Afn10P0F2.WlstMru_9100.MeterReadingDate), 2) + 0x33)
								default:
									da.WriteByte(gopsu.String2Int8("00000000", 2) + 0x33)
									da.WriteByte(gopsu.String2Int8(fmt.Sprintf("1001%02b00", pb2data.Afn10P0F2.WlstMru_9100.MeterReadingDate), 2) + 0x33)
								}
							}
							// 校验
							a := da.Bytes()
							l := len(a)
							x := 0
							for i := 4; i < l; i++ {
								x += int(a[i])
							}
							da.WriteByte(byte(x % 256))
							da.WriteByte(0x16)
						case "wlst.mru.1300":
							da.WriteByte(0x68)
							da.Write([]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa})
							da.WriteByte(0x68)
							da.Write([]byte{0x13, 0x0, 0xdf})
							da.WriteByte(0x16)
						}
						// 填充
						d.Write([]byte{byte(da.Len() % 256), byte(da.Len() / 256)})
						a := da.Bytes()
						d.Write(gopsu.CountCrc16VB(&a))
						d.Write(da.Bytes())

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
					DataDst: fmt.Sprintf("gb-open-%d-%s", pb2data.DataID.Addr, pb2data.DataID.Area),
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
