package shv1

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/xyzj/gopsu"
	wlstsh "github.com/xyzj/proto/msgshv1"
)

// ParseTml 解析上海路灯协议
func (dp *DataProcessor) ParseTml(d []byte) (r *Rtb) {
	r = &Rtb{}
	defer func() {
		if ex := recover(); ex != nil {
			r.Src = gopsu.Bytes2String(d, "-")
			r.Ex = fmt.Sprintf("Parse Tml error: %+v", errors.WithStack(ex.(error)))
		}
	}()
	if len(d) < 23 {
		r.Src = gopsu.Bytes2String(d, "-")
		r.Ex = "data is not long enough"
		return r
	}
LOOP:
	for k, v := range d {
		if len(d)-k < 23 {
			break
		}
		switch v {
		case 0x68:
			l := int(d[k+1]) + int(d[k+2])*256
			if d[k+5] == 0x68 && d[k+5+l+3] == 0x16 {
				dp.Version = 1
				r.Do = append(r.Do, dp.dataV1(d[k+6:k+5+l+3])...)
				d = d[k+5+l+4:]
				goto LOOP
			}
		}
	}
	return r
}

// v1版
func (dp *DataProcessor) dataV1(d []byte) []*Fwd {
	lstf := make([]*Fwd, 0)
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      TraDirect,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}
	if !gopsu.CheckCrc16VB(d) {
		f.Ex = fmt.Sprintf("shv1 data validation fails")
		lstf = append(lstf, f)
		return lstf
	}
	f.Addr = int64(gopsu.BcdBytes2Float64(d[:8], 0, true))
	msg := &wlstsh.MsgSHv1{
		DataID: &wlstsh.DataIdentification{},
	}
	msg.DataID.Addr = f.Addr
	msg.DataID.Afn = int32(d[8] << 3 >> 3)
	msg.DataID.Dir = int32(d[8] >> 7)
	msg.DataID.Seq = int32(d[9] << 4 >> 4)
	f.DataCmd = fmt.Sprintf("shv1.rtu.%02x", msg.DataID.Afn)
	// 处理con
	if d[9]<<3>>7 == 1 {
		ff := &Fwd{
			Addr:     f.Addr,
			DataCmd:  fmt.Sprintf("shv1.rtu.%02x", msg.DataID.Afn),
			DataType: DataTypeBytes,
			DataDst:  fmt.Sprintf("shv1-rtu-%d", f.Addr),
			DstType:  SockTml,
			DataSP:   SendLevelHigh,
			DataMsg:  dp.BuildCommand([]byte{0, 0, 1, 0}, f.Addr, 0, 0, 0, msg.DataID.Seq),
			Tra:      TraDirect,
			Job:      JobSend,
			Src:      gopsu.Bytes2String(d, "-"),
		}
		lstf = append(lstf, ff)
	}
	// 数据段长度
	l := len(d) - 2
	// 处理额外数据
	acd := d[8] << 2 >> 7
	if acd == 1 {
		// 处理ec
		l = l - 2
		msg.DataID.Ec1 = int32(d[len(d)-4])
		msg.DataID.Ec2 = int32(d[len(d)-3])
	}
	j := 10
	for {
		if j >= l {
			break
		}
		uid := &wlstsh.UnitIdentification{
			Pn: getPnFn(d[10:12]),
			Fn: getPnFn(d[12:14]),
		}
		j += 4
		msg.DataID.UintID = append(msg.DataID.UintID, uid)

		switch msg.DataID.Afn {
		case 0x00: // 确认∕否认
			switch uid.Pn {
			case 0:
				switch uid.Fn {
				case 1: // 全部确认
				case 2: // 全部否认
				}
			}
		case 0x02:
			switch uid.Pn {
			case 0:
				f.DataCmd = ""
				switch uid.Fn {
				case 1: // 登录
				case 3: // 心跳
					dp.Verbose.Store("signal", int32(float32(d[j])/31.0*100))
					j++
				}
			}
		case 0x09:
			switch uid.Pn {
			case 0:
				switch uid.Fn {
				case 1: // 终端信息
					msg.Afn09P0F1 = &wlstsh.Afn09_P0_F1{}
					msg.Afn09P0F1.CompanyCode = string(d[j : j+4])
					j += 4
					msg.Afn09P0F1.CompanyDevCode = string(d[j : j+8])
					j += 8
					msg.Afn09P0F1.DevSoftVer = string(d[j : j+4])
					j += 4
					msg.Afn09P0F1.DevSoftDate = gopsu.Bytes2String(d[j:j+3], "")
					j += 3
					msg.Afn09P0F1.DevCapacity = string(d[j : j+11])
					j += 11
					msg.Afn09P0F1.DevComVer = string(d[j : j+4])
					j += 4
					msg.Afn09P0F1.DevHardVer = string(d[j : j+4])
					j += 4
					msg.Afn09P0F1.ChipModule = string(d[j : j+8])
					j += 8
					msg.Afn09P0F1.DevHardDate = gopsu.Bytes2String(d[j:j+3], "")
					j += 3
					msg.Afn09P0F1.ContainRelay = int32(d[j])
					j++
					msg.Afn09P0F1.DevModule = int32(d[j])
					j++
					msg.Afn09P0F1.DevManufactureDate = gopsu.Bytes2String(d[j:j+3], "")
					j += 3
				}
			}
		case 0x0a:
			switch uid.Pn {
			case 0:
				switch uid.Fn {
				case 3: // 事件记录标识
					msg.Afn0AP0F3 = &wlstsh.Afn04_P0_F3{}
					var s string
					for i := 0; i < 8; i++ {
						s += gopsu.ReverseString(fmt.Sprintf("%08b", d[j]))
						j++
					}
					for k, v := range s {
						if v == 49 {
							msg.Afn0AP0F3.Normal = append(msg.Afn0AP0F3.Normal, int32(k+1))
						}
					}
					s = ""
					for i := 0; i < 8; i++ {
						s += gopsu.ReverseString(fmt.Sprintf("%08b", d[j]))
						j++
					}
					for k, v := range s {
						if v == 49 {
							msg.Afn0AP0F3.Import = append(msg.Afn0AP0F3.Import, int32(k+1))
						}
					}
					s = ""
					for i := 0; i < 8; i++ {
						s += gopsu.ReverseString(fmt.Sprintf("%08b", d[j]))
						j++
					}
					for k, v := range s {
						if v == 49 {
							msg.Afn0AP0F3.Report = append(msg.Afn0AP0F3.Report, int32(k+1))
						}
					}
				case 4: // 基本信息
					msg.Afn0AP0F4 = &wlstsh.Afn04_P0_F4{}
					msg.Afn0AP0F4.CboxNumber = int64(gopsu.BcdBytes2Float64(d[j:j+6], 0, true))
					j += 6
					msg.Afn0AP0F4.TmlPhyid = int64(gopsu.BcdBytes2Float64(d[j:j+8], 0, true))
					j += 8
					msg.Afn0AP0F4.Longitude = gopsu.BcdBytes2Float64(d[j:j+5], 2, true) / 100000.0
					j += 5
					msg.Afn0AP0F4.Latitude = gopsu.BcdBytes2Float64(d[j:j+5], 2, true) / 100000.0
					j += 5
					msg.Afn0AP0F4.UseSlu = int32(d[j])
					j++
					msg.Afn0AP0F4.SluFreq = int32(d[j]) + int32(d[j+1])*256
					j += 2
				case 9: // 开关灯时间
					msg.Afn0AP0F9 = &wlstsh.Afn04_P0_F9{}
					msg.Afn0AP0F9.DtStart = fmt.Sprintf("%02d%02d", d[j], d[j+1])
					j += 2
					msg.Afn0AP0F9.Days = int32(d[j]) + int32(d[j+1])*256
					j += 2
					for i := int32(0); i < msg.Afn0AP0F9.Days; i++ {
						ts := &wlstsh.Afn04_P0_F9_Time_Slot{}
						ts.TimeOn = gopsu.Bcd2STime([]byte{d[j+1], d[j]})
						j += 2
						ts.TimeOff = gopsu.Bcd2STime([]byte{d[j+1], d[j]})
						j += 2
						msg.Afn0AP0F9.TimeSlot = append(msg.Afn0AP0F9.TimeSlot, ts)
					}
				case 12: // 控制回路参数
					msg.Afn0AP0F12 = &wlstsh.Afn04_P0_F12{}
					for k, v := range gopsu.ReverseString(fmt.Sprintf("%08b%08b", d[j+1], d[j])) {
						if v == 49 {
							msg.Afn0AP0F12.LoopNo = append(msg.Afn0AP0F12.LoopNo, int32(k+1))
						}
					}
					j += 2
					for k, v := range gopsu.ReverseString(fmt.Sprintf("%08b", d[j])) {
						if v == 49 {
							msg.Afn0AP0F12.EngNo = append(msg.Afn0AP0F12.EngNo, int32(k+1))
						}
					}
					j++
					msg.Afn0AP0F12.EngLevel = int32(d[j])
					j++
				case 25: // 状态量参数
					msg.Afn0AP0F25 = &wlstsh.Afn04_P0_F25{}
					n := int(d[j])
					j++
					msg.Afn0AP0F25.LoopStart = int32(d[j])
					j++
					for i := 0; i < n; i++ {
						li := &wlstsh.Afn04_P0_F25_Loop_Info{}
						li.Type = int32(d[j])
						j++
						li.InOut = int32(d[j] >> 7)
						li.LoopNo = int32(d[j] << 1 >> 1)
						j++
						li.Phase = int32(d[j])
						j++
						msg.Afn0AP0F25.LoopInfo = append(msg.Afn0AP0F25.LoopInfo, li)
					}
				case 26: // 模拟量参数
					msg.Afn0AP0F26 = &wlstsh.Afn04_P0_F26{}
					n := int(d[j])
					j++
					msg.Afn0AP0F26.LoopStart = int32(d[j])
					j++
					for i := 0; i < n; i++ {
						li := &wlstsh.Afn04_P0_F26_Loop_Data{}
						li.Using = int32(d[j])
						j++
						li.Type = int32(d[j])
						j++
						li.InOut = int32(d[j] >> 7)
						li.LoopNo = int32(d[j] << 1 >> 1)
						j++
						li.Phase = int32(d[j])
						j++
						// limit
						j += 8
						msg.Afn0AP0F26.LoopData = append(msg.Afn0AP0F26.LoopData, li)
					}
				}
			}
		case 0x0c:
			switch uid.Pn {
			case 0:
				switch uid.Fn {
				case 2: // 时钟
					msg.Afn0CP0F2 = &wlstsh.Afn05_P0_F31{}
					msg.Afn0CP0F2.Time = gopsu.Time2Stamp(fmt.Sprintf("20%02x-%02x-%02x %02x:%02x:%02x", d[j+5], d[j+4]<<3>>3, d[j+3], d[j+2], d[j+1], d[j]))
					j += 6
				case 11: // 批量查询模拟量
					msg.Afn0CP0F11 = &wlstsh.Afn0C_P0_F11{}
					n := int(d[j])
					j++
					msg.Afn0CP0F11.LoopStart = int32(d[j])
					j++
					for i := 0; i < n; i++ {
						li := &wlstsh.Afn0C_P0_F11_Loop_Data{}
						li.LoopNo = int32(d[j]) + msg.Afn0CP0F11.LoopStart
						j++
						li.Type = int32(d[j])
						j++
						// 数据解析
						switch li.Type {
						case 1, 2, 3, 4, 6, 8: // 电压,电流,有功,无功,频率,照度 a.2
							li.Data = decodeBCDA2(d[j : j+2])
						case 5, 7: // 功率因数,相角 a.5
							li.Data = decodeBCDA5(d[j : j+2])
						}
						j += 2
						msg.Afn0CP0F11.LoopData = append(msg.Afn0CP0F11.LoopData, li)
					}
				case 12: // 批量查询状态量
					msg.Afn0CP0F12 = &wlstsh.Afn0C_P0_F12{}
					n := int(d[j])
					j++
					msg.Afn0CP0F12.LoopStart = int32(d[j])
					j++
					for i := 0; i < n; i++ {
						li := &wlstsh.Afn0C_P0_F12_Loop_Status{}
						li.LoopNo = int32(d[j]) + msg.Afn0CP0F12.LoopStart
						j++
						// 数据解析
						li.Status = int32(d[j])
						j++
						msg.Afn0CP0F12.LoopStatus = append(msg.Afn0CP0F12.LoopStatus, li)
					}
				}
			}
		case 0x0e:
			switch uid.Pn {
			case 0:
				switch uid.Fn {
				case 1: // 重要事件
					msg.Afn0EP0F1 = &wlstsh.Afn0E_P0_F1{}
					msg.DataID.Ec1 = int32(d[j])
					j++
					msg.DataID.Ec2 = int32(d[j])
					j++
					msg.Afn0EP0F1.Pm = int32(d[j])
					j++
					msg.Afn0EP0F1.Pn = int32(d[j])
					j++
					var y int32
					if msg.Afn0EP0F1.Pm < msg.Afn0EP0F1.Pn {
						y = msg.Afn0EP0F1.Pn - msg.Afn0EP0F1.Pm
					} else {
						y = 256 + msg.Afn0EP0F1.Pn - msg.Afn0EP0F1.Pm
					}
					for i := int32(0); i < y; i++ {
						ei := &wlstsh.Afn0E_P0_F1_Events_Data{}
						ei.ErcId = int32(d[j])
						j++
						l := int(d[j])
						j++
						ei.DtReport = gopsu.BcdDT2Stamp(d[j : j+5])
						j += 5
						switch ei.ErcId {
						case 1: // 掉电
							ei.Erc01 = &wlstsh.Afn0E_P0_F1_Erc01_Data{
								Type: int32(d[j]),
							}
						case 6: // 异常开灯
							ei.Erc06 = &wlstsh.Afn0E_P0_F1_Erc06_Data{
								Type: int32(d[j]),
								Why:  int32(d[j+1]),
							}
						case 7: // 异常关灯
							ei.Erc07 = &wlstsh.Afn0E_P0_F1_Erc06_Data{
								Type: int32(d[j]),
								Why:  int32(d[j+1]),
							}
						}
						j += l - 5
					}
				case 2: // 一般事件
					msg.Afn0EP0F2 = &wlstsh.Afn0E_P0_F1{}
				}
			}
		}
	}
	if len(f.DataCmd) > 0 {
		f.DataMsg, _ = msg.Marshal()
		lstf = append(lstf, f)
	}
	return lstf
}
