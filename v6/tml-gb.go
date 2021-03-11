package v6

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
	"github.com/xyzj/gopsu"
	msgopen "github.com/xyzj/proto/msgwlst"
)

// ProcessGBOpen 处理国标协议
func (dp *DataProcessor) ProcessGBOpen(d []byte) (r *Rtb) {
	r = &Rtb{}
	defer func() {
		if ex := recover(); ex != nil {
			r.Src = gopsu.Bytes2String(d, "-")
			r.Ex = fmt.Sprintf("%+v", errors.WithStack(ex.(error)))
		}
	}()
LOOP:
	if len(d) < 21 {
		if bytes.ContainsAny(d, "h") {
			r.Unfinish = d
		}
		return r
	}
	for k, v := range d {
		if v == 0x68 { // 公司标准（天津版）
			lgb := int(d[k+1]) + int(d[k+2])*256
			if d[k+5] == 0x68 && d[k+lgb+7] == 0x16 {
				r.Do = append(r.Do, dp.dataGBOpen(d[k:k+lgb+8])...)
				d = d[k+lgb+8:]
				goto LOOP
			}
		}
	}
	return r
}

// 国标协议
func (dp *DataProcessor) dataGBOpen(d []byte) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      TraDirect,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}
	ll := int(d[1]) + int(d[2])*256

	if d[6+ll] != dp.CalculateRC(d[6:6+ll]) { // 校验失败，丢弃
		return lstf
	}
	afn := d[13]                     // 应用功能码
	fun := byte(d[6]<<4) >> 4        // 链路功能码
	dir := d[6] >> 7                 // 数据方向
	acd := int32(byte(d[6]<<2) >> 7) // 是否含附加数据
	tpv := byte(d[14]) >> 7          // 是否含时间标签
	seq := byte(d[14]<<4) >> 4       // 上行序号
	con := byte(d[14]<<3) >> 7       // 主动上行数据，0-不需要应答，1-应答
	var ec1, ec2 int32               // ec1,ec2,重要事件/事件数量
	var j, maxJ int                  // 数据读取索引，数据单元最大索引
	maxJ = len(d) - 2
	if acd == 1 { // 有附加数据
		if tpv == 1 { // 有时间戳
			maxJ = len(d) - 10
		} else {
			maxJ = len(d) - 4
		}
		ec1 = int32(d[maxJ])
		ec2 = int32(d[maxJ+1])
	}
	j = 15
	// 初始化框架
	f.Addr = int64(d[10]) + int64(d[11])*256
	f.Area = fmt.Sprintf("%02x%02x", d[9], d[8])
	f.DataCmd = fmt.Sprintf("gb.open.%02x%02x", fun, afn)
	svrmsg := &msgopen.MsgGBOpen{
		DataID: &msgopen.DataIdentification{
			Ec1:  ec1,
			Ec2:  ec2,
			Afn:  int32(afn),
			Fun:  int32(fun),
			Seq:  int32(seq),
			Dir:  int32(dir),
			Addr: f.Addr,
			Area: f.Area,
		},
	}
	// 通用应答数据体
	var dAns = []byte{0, 0, 1, 0, afn}
	// 循环解析所有数据单元
	for {
		// 当读到最后时，跳出循环
		if j >= maxJ { // 上行数据无视tp，pw
			break
		}
		uid := &msgopen.UnitIdentification{
			Pn: getPnFn(d[j : j+2]),
			Fn: getPnFn(d[j+2 : j+4]),
		}
		j += 4
		svrmsg.DataID.UintID = append(svrmsg.DataID.UintID, uid)
		switch afn {
		case 0x00: // 应答
			switch uid.Pn {
			case 0:
				switch uid.Fn {
				case 1: // 全部确认
					svrmsg.Afn00P0F1 = &msgopen.Afn00_P0_F1{}
					svrmsg.Afn00P0F1.Afn = int32(d[j])
					j++
				case 2: // 全部否认
					svrmsg.Afn00P0F2 = &msgopen.Afn00_P0_F1{}
					svrmsg.Afn00P0F2.Afn = int32(d[j])
					j++
				case 3: // 部分确认/否认
					svrmsg.Afn00P0F3 = &msgopen.Afn00_P0_F3{}
					svrmsg.Afn00P0F3.Afn = int32(d[j])
					j++
					for {
						svrmsg.Afn00P0F3.UnitId = append(svrmsg.Afn00P0F3.UnitId, &msgopen.UnitIdentification{
							Pn: getPnFn(d[j : j+2]),
							Fn: getPnFn(d[j+2 : j+4]),
						})
						j += 4
						svrmsg.Afn00P0F3.Status = append(svrmsg.Afn00P0F3.Status, int32(d[j])^1)
						j++
						if j >= maxJ {
							break
						}
					}
				}
			}
		case 0x02: // 登录/心跳
			if uid.Pn == 0 && uid.Fn == 1 { // 仅登录消息的areaid有效
				dp.AreaCode = fmt.Sprintf("%02x%02x", d[9], d[8])
			}
			f.DataCmd = ""
		case 0x09: // 请求终端配置及信息
			switch uid.Pn {
			case 0:
				switch uid.Fn {
				case 1: // 终端版本信息
					svrmsg.Afn09P0F1 = &msgopen.Afn09_P0_F1{}
					svrmsg.Afn09P0F1.Company = gopsu.TrimString(string(d[j : j+4]))
					j += 4
					svrmsg.Afn09P0F1.DeviceNum = gopsu.TrimString(string(d[j : j+8]))
					j += 8
					svrmsg.Afn09P0F1.SoftwareVer = gopsu.TrimString(string(d[j : j+8]))
					j += 8
					svrmsg.Afn09P0F1.SoftwareDate = int32(gopsu.BcdBytes2Float64(d[j:j+3], 0, true))
					j += 3
					svrmsg.Afn09P0F1.DeviceInfo = gopsu.TrimString(string(d[j : j+16]))
					j += 16
					svrmsg.Afn09P0F1.HardwareVer = gopsu.TrimString(string(d[j : j+8]))
					j += 8
					svrmsg.Afn09P0F1.HardwareDate = int32(gopsu.BcdBytes2Float64(d[j:j+3], 0, true))
					j += 3
					svrmsg.Afn09P0F1.RemoteComVer = gopsu.TrimString(string(d[j : j+8]))
					j += 8
					svrmsg.Afn09P0F1.RemoteComDate = int32(gopsu.BcdBytes2Float64(d[j:j+3], 0, true))
					j += 3
					svrmsg.Afn09P0F1.LocalComVer = gopsu.TrimString(string(d[j : j+8]))
					j += 8
					svrmsg.Afn09P0F1.LocalComDate = int32(gopsu.BcdBytes2Float64(d[j:j+3], 0, true))
					j += 3
				}
			}
		case 0x0a: // 查询参数
			switch uid.Pn {
			case 0:
				switch uid.Fn {
				case 1: // 终端上行通信口通信参数设置
					svrmsg.Afn0AP0F1 = &msgopen.Afn04_P0_F1{}
					svrmsg.Afn0AP0F1.Rts = int32(d[j])
					j++
					svrmsg.Afn0AP0F1.MasterRts = int32(d[j])
					j++
					s := fmt.Sprintf("%08b%08b", d[j+1], d[j])
					j += 2
					svrmsg.Afn0AP0F1.ResendTimeout = gopsu.String2Int32(s[2:4], 2)
					svrmsg.Afn0AP0F1.ResendNum = gopsu.String2Int32(s[4:], 2)
					ss := gopsu.SplitStringWithLen(gopsu.ReverseString(fmt.Sprintf("%08b", d[j])), 1)
					j++
					for _, v := range ss {
						svrmsg.Afn0AP0F1.ReportMark = append(svrmsg.Afn0AP0F1.ReportMark, gopsu.String2Int32(v, 10))
					}
					svrmsg.Afn0AP0F1.KeepAlive = int32(d[j])
					j++
				case 3: // 主站 IP 地址  和端口
					svrmsg.Afn0AP0F3 = &msgopen.Afn04_P0_F3{}
					t := d[j]
					j++
					switch t {
					case 1: // ipv4
						svrmsg.Afn0AP0F3.MainIp = fmt.Sprintf("%d.%d.%d.%d", d[j], d[j+1], d[j+2], d[j+3])
						j += 4
					case 2: // ipv6
						j += 16
					}
					svrmsg.Afn0AP0F3.MainPort = int32(d[j]) + int32(d[j+1])
					j += 2
					t = d[j]
					j++
					switch t {
					case 1: // ipv4
						svrmsg.Afn0AP0F3.BackupIp = fmt.Sprintf("%d.%d.%d.%d", d[j], d[j+1], d[j+2], d[j+3])
						j += 4
					case 2: // ipv6
						j += 16
					}
					svrmsg.Afn0AP0F3.BackupPort = int32(d[j]) + int32(d[j+1])
					j += 2
					svrmsg.Afn0AP0F3.Apn = gopsu.TrimString(string(d[j : j+16]))
					j += 16
					svrmsg.Afn0AP0F3.User = gopsu.TrimString(string(d[j : j+32]))
					j += 32
					svrmsg.Afn0AP0F3.Pwd = gopsu.TrimString(string(d[j : j+32]))
					j += 32
				case 9: // 终端事件记录配置设置
					svrmsg.Afn0AP0F9 = &msgopen.Afn04_P0_F9{}
					svrmsg.Afn0AP0F9.EventsAvailable = make([]int32, 0)
					ss := gopsu.SplitStringWithLen(gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b%08b%08b%08b%08b%08b", d[j+7], d[j+6], d[j+5], d[j+4], d[j+3], d[j+2], d[j+1], d[j])), 1)
					j += 8
					for k, v := range ss {
						if v == "1" {
							svrmsg.Afn0AP0F9.EventsAvailable = append(svrmsg.Afn0AP0F9.EventsAvailable, int32(k)+1)
						}
					}
					svrmsg.Afn0AP0F9.EventsReport = make([]int32, 0)
					ss = gopsu.SplitStringWithLen(gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b%08b%08b%08b%08b%08b", d[j+7], d[j+6], d[j+5], d[j+4], d[j+3], d[j+2], d[j+1], d[j])), 1)
					j += 8
					for k, v := range ss {
						if v == "1" {
							svrmsg.Afn0AP0F9.EventsReport = append(svrmsg.Afn0AP0F9.EventsReport, int32(k)+1)
						}
					}
				case 10: // 设备状态输入参数
					svrmsg.Afn0AP0F10 = &msgopen.Afn04_P0_F10{}
					svrmsg.Afn0AP0F10.SwitchinAvailable = make([]int32, 32)
					ss := gopsu.SplitStringWithLen(gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])), 1)
					j += 4
					for k, v := range ss {
						svrmsg.Afn0AP0F10.SwitchinAvailable[k] = gopsu.String2Int32(v, 10)
					}
					svrmsg.Afn0AP0F10.SwitchinHopping = make([]int32, 32)
					ss = gopsu.SplitStringWithLen(gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])), 1)
					j += 4
					for k, v := range ss {
						svrmsg.Afn0AP0F10.SwitchinHopping[k] = gopsu.String2Int32(v, 10)
					}
				case 11: // GPS经纬度
					svrmsg.Afn0AP0F11 = &msgopen.Afn04_P0_F11{}
					svrmsg.Afn0AP0F11.LongitudeMark = int32(d[j])
					j++
					svrmsg.Afn0AP0F11.Longitude = gopsu.DFM2GPS(int(d[j]), int(d[j+1]), float64(d[j+2])+float64(d[j+3])*256)
					j += 4
					svrmsg.Afn0AP0F11.LatitudeMark = int32(d[j])
					j++
					svrmsg.Afn0AP0F11.Latitude = gopsu.DFM2GPS(int(d[j]), int(d[j+1]), float64(d[j+2])+float64(d[j+3])*256)
					j += 4
				case 14: // 扩展设备配置参数(看不懂)
				case 41: // 开关量输出参数关联
					svrmsg.Afn0AP0F41 = &msgopen.Afn04_P0_F41{}
					x := int(d[j])
					j++
					for i := 0; i < x; i++ {
						svrmsg.Afn0AP0F41.SwitchoutLoops = append(svrmsg.Afn0AP0F41.SwitchoutLoops, int32(d[j]))
						j++
					}
				case 42: // 模拟量采集参数关联
					svrmsg.Afn0AP0F42 = &msgopen.Afn04_P0_F42{}
					svrmsg.Afn0AP0F42.VoltageTransformer = int32(d[j])
					j++
					svrmsg.Afn0AP0F42.EnergyATransformer = int32(d[j])
					j++
					svrmsg.Afn0AP0F42.EnergyBTransformer = int32(d[j])
					j++
					svrmsg.Afn0AP0F42.EnergyCTransformer = int32(d[j])
					j++
					x := int(d[j])
					j++
					for i := 0; i < x; i++ {
						cs := &msgopen.Afn04_P0_F42_Current_Setting{}
						cs.Transformer = int32(d[j])
						j++
						cs.Phase = int32(d[j])
						j++
						svrmsg.Afn0AP0F42.CurrentSetting = append(svrmsg.Afn0AP0F42.CurrentSetting, cs)
					}
				case 46: // 周回路控制表
					svrmsg.Afn0AP0F46 = &msgopen.Afn04_P0_F46{}
					ts := &msgopen.Afn04_P0_F46_Time_Slot{}
					// 周日
					for i := 0; i < 8; i++ {
						ts.TimeOn = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						ts.TimeOff = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						svrmsg.Afn0AP0F46.WeekDay7 = append(svrmsg.Afn0AP0F46.WeekDay7, ts)
					}
					// 周1
					for i := 0; i < 8; i++ {
						ts.TimeOn = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						ts.TimeOff = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						svrmsg.Afn0AP0F46.WeekDay1 = append(svrmsg.Afn0AP0F46.WeekDay1, ts)
					}
					// 周2
					for i := 0; i < 8; i++ {
						ts.TimeOn = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						ts.TimeOff = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						svrmsg.Afn0AP0F46.WeekDay2 = append(svrmsg.Afn0AP0F46.WeekDay2, ts)
					}
					// 周三
					for i := 0; i < 8; i++ {
						ts.TimeOn = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						ts.TimeOff = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						svrmsg.Afn0AP0F46.WeekDay3 = append(svrmsg.Afn0AP0F46.WeekDay3, ts)
					}
					// 周四
					for i := 0; i < 8; i++ {
						ts.TimeOn = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						ts.TimeOff = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						svrmsg.Afn0AP0F46.WeekDay4 = append(svrmsg.Afn0AP0F46.WeekDay4, ts)
					}
					// 周五
					for i := 0; i < 8; i++ {
						ts.TimeOn = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						ts.TimeOff = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						svrmsg.Afn0AP0F46.WeekDay5 = append(svrmsg.Afn0AP0F46.WeekDay5, ts)
					}
					// 周六
					for i := 0; i < 8; i++ {
						ts.TimeOn = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						ts.TimeOff = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						svrmsg.Afn0AP0F46.WeekDay6 = append(svrmsg.Afn0AP0F46.WeekDay6, ts)
					}
				case 49: // 经纬度开关灯偏移
					svrmsg.Afn0AP0F49 = &msgopen.Afn04_P0_F49{}
					svrmsg.Afn0AP0F49.OffsetOn = gopsu.Byte2SignedInt32(d[j])
					j++
					svrmsg.Afn0AP0F49.OffsetOff = gopsu.Byte2SignedInt32(d[j])
					j++
				case 50: // 设定全数据上送周期
					svrmsg.Afn0AP0F50 = &msgopen.Afn04_P0_F50{}
					svrmsg.Afn0AP0F50.ReportTimer = int32(d[j])
					j++
				case 51: // 设置模拟量上下限(有疑问)
					svrmsg.Afn0AP0F51 = &msgopen.Afn04_P0_F51{}
					svrmsg.Afn0AP0F51.VoltageLowerLimit = gopsu.BcdBytes2Float64(d[j:j+2], 1, true)
					j += 2
					svrmsg.Afn0AP0F51.VoltageUpperLimit = gopsu.BcdBytes2Float64(d[j:j+2], 1, true)
					j += 2
					n := int(d[j])
					j++
					for i := 0; i < n; i++ {
						m := int(d[j])
						j++
						cs := &msgopen.Afn04_P0_F51_Current_Setting{}
						for ii := 0; ii < m; ii++ {
							ls := &msgopen.Afn04_P0_F51_Loop_Setting{}
							ls.TimeStart = gopsu.Bcd2STime(d[j : j+2])
							j += 2
							ls.TimeEnd = gopsu.Bcd2STime(d[j : j+2])
							j += 2
							ls.CurrentLowerLimit = gopsu.BcdBytes2Float64(d[j:j+3], 3, false)
							j += 2
							ls.CurrentUpperLimit = gopsu.BcdBytes2Float64(d[j:j+3], 3, false)
							j += 2
							cs.LoopSetting = append(cs.LoopSetting, ls)
						}
						svrmsg.Afn0AP0F51.CurrentSetting = append(svrmsg.Afn0AP0F51.CurrentSetting, cs)
					}
				case 52: // 设置漏电保护参数
					svrmsg.Afn0AP0F52 = &msgopen.Afn04_P0_F52{}
					for i := 0; i < 8; i++ {
						//ln := int32(d[j])
						j++
						svrmsg.Afn0AP0F52.LeakageLimit[i].LoopEnable = int32(d[j])
						j++
						svrmsg.Afn0AP0F52.LeakageLimit[i].LoopSwitchout = int32(d[j])
						j++
						svrmsg.Afn0AP0F52.LeakageLimit[i].Level1Limit = int32(gopsu.BcdBytes2Float64(d[j:j+3], 3, false) * 1000)
						j += 3
						svrmsg.Afn0AP0F52.LeakageLimit[i].Level2Limit = int32(gopsu.BcdBytes2Float64(d[j:j+3], 3, false) * 1000)
						j += 3
						svrmsg.Afn0AP0F52.LeakageLimit[i].Level3Limit = int32(gopsu.BcdBytes2Float64(d[j:j+3], 3, false) * 1000)
						j += 3
						svrmsg.Afn0AP0F52.LeakageLimit[i].Level4Limit = int32(gopsu.BcdBytes2Float64(d[j:j+3], 3, false) * 1000)
						j += 3

						if i != 7 {
							j += 4
						}
					}

				case 53: // 设置光照度限值 参数
					svrmsg.Afn0AP0F53 = &msgopen.Afn04_P0_F53{}
					svrmsg.Afn0AP0F53.LuxThreshold = int32(d[j]) + int32(d[j])*256
					j += 2
					svrmsg.Afn0AP0F53.TimeTick = int32(d[j])
					j++
				case 57: // 停运/投运
					svrmsg.Afn0AP0F57 = &msgopen.Afn04_P0_F57{}
					svrmsg.Afn0AP0F57.RuntimeMark = int32(d[j])
					j++
					// s := gopsu.SplitStringWithLen(gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b%08b%08b%08b", d[j+5], d[j+4], d[j+3], d[j+2], d[j+1], d[j])), 1)
					j += 6
					// for _, v := range s {
					// 	svrmsg.Afn0AP0F57.LoopMark = append(svrmsg.Afn0AP0F57.LoopMark, gopsu.String2Int32(v, 10))
					// }
				case 65: // 电流回路矢量
					svrmsg.Afn0AP0F65 = &msgopen.Afn04_P0_F65{}
					x := int(d[j])
					j++
					for i := 0; i < x; i++ {
						svrmsg.Afn0AP0F65.SwitchinVector = append(svrmsg.Afn0AP0F65.SwitchinVector, int32(d[j]))
						j++
					}
				case 66: // 电流回路遥信矢量
					svrmsg.Afn0AP0F66 = &msgopen.Afn04_P0_F66{}
					x := int(d[j])
					j++
					for i := 0; i < x; i++ {
						svrmsg.Afn0AP0F66.SwitchinSwitchout = append(svrmsg.Afn0AP0F66.SwitchinSwitchout, int32(d[j]))
						j++
					}
				case 67: // 开关量输出矢量
					svrmsg.Afn0AP0F67 = &msgopen.Afn04_P0_F67{}
					x := int(d[j])
					j++
					for i := 0; i < x; i++ {
						svrmsg.Afn0AP0F67.SwitchoutVector = append(svrmsg.Afn0AP0F67.SwitchoutVector, int32(d[j]))
						j++
					}
				case 68: // 断电保护参数
					svrmsg.Afn0AP0F68 = &msgopen.Afn04_P0_F68{}
					svrmsg.Afn0AP0F68.VoltageLowerBreak = int32(d[j])
					j += 3
					svrmsg.Afn0AP0F68.VoltageLowerLimit = gopsu.BcdBytes2Float64(d[j:j+2], 1, true)
					j += 3
					svrmsg.Afn0AP0F68.VoltageUpperBreak = int32(d[j])
					j += 3
					svrmsg.Afn0AP0F68.VoltageUpperLimit = gopsu.BcdBytes2Float64(d[j:j+2], 1, true)
					j += 3
				}
			default:
				switch uid.Fn {
				case 15: // 继电器输出控制方案（年设置）
					if svrmsg.Afn0APnF15 == nil {
						svrmsg.Afn0APnF15 = make([]*msgopen.Afn04_Pn_F15, 0)
					}
					pndata := &msgopen.Afn04_Pn_F15{}
					pndata.DtStart = fmt.Sprintf("%d", int32(gopsu.BcdBytes2Float64(d[j:j+3], 0, true)))
					j += 3
					pndata.DtDays = int32(d[j])
					j++
					pndata.SwitchoutNo = make([]int32, 16)
					ss := gopsu.SplitStringWithLen(gopsu.ReverseString(fmt.Sprintf("%08b%08b", d[j], d[j+1])), 1)
					for k, v := range ss {
						pndata.SwitchoutNo[k] = gopsu.String2Int32(v, 10)
					}
					j += 2
					x := int(d[j]) // 时段数
					j++
					for i := 0; i < x; i++ {
						ts := &msgopen.Afn04_Pn_F15_Time_Slot{}
						ts.TimeOn = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						ts.TimeOff = gopsu.Bcd2STime(d[j : j+2])
						j += 2
						pndata.TimeSlot = append(pndata.TimeSlot, ts)
					}
					svrmsg.Afn0APnF15 = append(svrmsg.Afn0APnF15, pndata)
				}
			}
		case 0x0c: // 请求实时数据
			switch uid.Pn {
			case 0:
				switch uid.Fn {
				case 2: // 终端日历时钟
					svrmsg.Afn0CP0F2 = &msgopen.Afn0C_P0_F2{}
					svrmsg.Afn0CP0F2.TimeUnix = gopsu.BcdDT2Stamp(d[j : j+6])
					j += 6
				case 3: // 进线模拟量数据(全数据)(报警主报)
					svrmsg.Afn0CP0F3 = &msgopen.Afn0C_P0_F3{}
					svrmsg.Afn0CP0F3.Frequency = gopsu.BcdBytes2Float64(d[j:j+2], 1, true)
					j += 2
					svrmsg.Afn0CP0F3.PhaseData = make([]*msgopen.Afn0C_P0_F3_Phase_Data, 3)
					for i := 0; i < 3; i++ {
						pd := &msgopen.Afn0C_P0_F3_Phase_Data{}
						svrmsg.Afn0CP0F3.PhaseData[i] = pd
					}
					// 电压
					svrmsg.Afn0CP0F3.PhaseData[0].Voltage = gopsu.BcdBytes2Float64(d[j:j+2], 1, true)
					j += 2
					svrmsg.Afn0CP0F3.PhaseData[1].Voltage = gopsu.BcdBytes2Float64(d[j:j+2], 1, true)
					j += 2
					svrmsg.Afn0CP0F3.PhaseData[2].Voltage = gopsu.BcdBytes2Float64(d[j:j+2], 1, true)
					j += 2
					// 电流
					svrmsg.Afn0CP0F3.PhaseData[0].Current = gopsu.BcdBytes2Float64(d[j:j+3], 3, false)
					j += 3
					svrmsg.Afn0CP0F3.PhaseData[1].Current = gopsu.BcdBytes2Float64(d[j:j+3], 3, false)
					j += 3
					svrmsg.Afn0CP0F3.PhaseData[2].Current = gopsu.BcdBytes2Float64(d[j:j+3], 3, false)
					j += 3
					// 功率因数
					svrmsg.Afn0CP0F3.PhaseData[0].PowerFactor = gopsu.BcdBytes2Float64(d[j:j+2], 1, false)
					j += 2
					svrmsg.Afn0CP0F3.PhaseData[1].PowerFactor = gopsu.BcdBytes2Float64(d[j:j+2], 1, false)
					j += 2
					svrmsg.Afn0CP0F3.PhaseData[2].PowerFactor = gopsu.BcdBytes2Float64(d[j:j+2], 1, false)
					j += 2
					// 有功功率
					svrmsg.Afn0CP0F3.PhaseData[0].ActivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
					j += 3
					svrmsg.Afn0CP0F3.PhaseData[1].ActivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
					j += 3
					svrmsg.Afn0CP0F3.PhaseData[2].ActivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
					j += 3
					// 无功功率
					svrmsg.Afn0CP0F3.PhaseData[0].ReactivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
					j += 3
					svrmsg.Afn0CP0F3.PhaseData[1].ReactivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
					j += 3
					svrmsg.Afn0CP0F3.PhaseData[2].ReactivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
					j += 3
					// 有功电能
					svrmsg.Afn0CP0F3.PhaseData[0].ActiveEnergy = gopsu.BcdBytes2Float64(d[j:j+4], 2, true)
					j += 4
					svrmsg.Afn0CP0F3.PhaseData[1].ActiveEnergy = gopsu.BcdBytes2Float64(d[j:j+4], 2, true)
					j += 4
					svrmsg.Afn0CP0F3.PhaseData[2].ActiveEnergy = gopsu.BcdBytes2Float64(d[j:j+4], 2, true)
					j += 4
					// 无功电能
					svrmsg.Afn0CP0F3.PhaseData[0].ReactiveEnergy = gopsu.BcdBytes2Float64(d[j:j+4], 2, true)
					j += 4
					svrmsg.Afn0CP0F3.PhaseData[1].ReactiveEnergy = gopsu.BcdBytes2Float64(d[j:j+4], 2, true)
					j += 4
					svrmsg.Afn0CP0F3.PhaseData[2].ReactiveEnergy = gopsu.BcdBytes2Float64(d[j:j+4], 2, true)
					j += 4
				case 4: // 终端上行通信状态
					svrmsg.Afn0CP0F4 = &msgopen.Afn0C_P0_F4{}
					svrmsg.Afn0CP0F4.EnableReport = int32(byte(d[j] << 6))
					j++
				case 6: // 终端当前控制状态
					svrmsg.Afn0CP0F6 = &msgopen.Afn0C_P0_F6{}
					s := gopsu.SplitStringWithLen(gopsu.ReverseString(fmt.Sprintf("%08b%08b", d[j+1], d[j])), 1)
					j += 2
					for _, v := range s {
						svrmsg.Afn0CP0F6.SwitchoutStatus = append(svrmsg.Afn0CP0F6.SwitchoutStatus, gopsu.String2Int32(v, 10))
					}
				case 7: // 终端事件计数器当前值
					svrmsg.Afn0CP0F7 = &msgopen.Afn0C_P0_F7{
						Ec1: int32(d[j]),
						Ec2: int32(d[j]),
					}
					j += 2
				case 9: // 终端状态量及变位标志(全数据)
					svrmsg.Afn0CP0F9 = &msgopen.Afn0C_P0_F9{}
					svrmsg.Afn0CP0F9.LoopStatus = make([]*msgopen.Afn0C_P0_F9_Loop_Status, 32)
					for i := 0; i < 32; i++ {
						ls := &msgopen.Afn0C_P0_F9_Loop_Status{}
						svrmsg.Afn0CP0F9.LoopStatus[i] = ls
					}
					s := gopsu.SplitStringWithLen(gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])), 1)
					j += 4
					for k, v := range s {
						svrmsg.Afn0CP0F9.LoopStatus[k].StNow = gopsu.String2Int32(v, 10)

					}
					s = gopsu.SplitStringWithLen(gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])), 1)
					j += 4
					for k, v := range s {
						svrmsg.Afn0CP0F9.LoopStatus[k].StChanged = gopsu.String2Int32(v, 10)
					}
				case 18: // 终端回路事件报警状态(全数据)
					svrmsg.Afn0CP0F18 = &msgopen.Afn0C_P0_F18{}
					svrmsg.Afn0CP0F18.LoopNo = int32(d[j])
					j++
					svrmsg.Afn0CP0F18.LoopPhase = int32(d[j])
					j++
					svrmsg.Afn0CP0F18.EventsDo = make([]int32, 64)
					s := gopsu.SplitStringWithLen(gopsu.ReverseString(fmt.Sprintf("%08b%08b%08b%08b%08b%08b%08b%08b", d[j+7], d[j+6], d[j+5], d[j+4], d[j+3], d[j+2], d[j+1], d[j])), 1)
					j += 8
					for k, v := range s {
						svrmsg.Afn0CP0F18.EventsDo[k] = gopsu.String2Int32(v, 10)
					}
				case 19: // 漏电检测数据(全数据)
					svrmsg.Afn0CP0F19 = &msgopen.Afn0C_P0_F19{}
					x := int(d[j])
					j++
					for i := 0; i < x; i++ {
						svrmsg.Afn0CP0F19.LeakageCurrent = append(svrmsg.Afn0CP0F19.LeakageCurrent, gopsu.BcdBytes2Float64(d[j:j+3], 3, false))
						j += 3
					}
				case 20: // 光照度数据(主报)
					svrmsg.Afn0CP0F20 = &msgopen.Afn0C_P0_F20{}
					svrmsg.Afn0CP0F20.Lux = gopsu.BcdBytes2Float64(d[j:j+2], 0, true)
					j += 2
					svrmsg.Afn0CP0F20.Temperature = gopsu.BcdBytes2Float64(d[j:j+2], 1, false)
					j += 2
				}
			default:
				switch uid.Fn {
				case 1: // 出线模拟量数据(全数据)(报警主报)
					svrmsg.Afn0CPnF1 = &msgopen.Afn0C_Pn_F1{}
					svrmsg.Afn0CPnF1.DtReport = gopsu.BcdDT2Stamp(d[j : j+5])
					j += 5
					x := int(d[j])
					j++
					svrmsg.Afn0CPnF1.LoopData = make([]*msgopen.Afn0C_Pn_F1_Loop_Data, x)
					for i := 0; i < x; i++ {
						ld := &msgopen.Afn0C_Pn_F1_Loop_Data{
							LoopNo: int32(i) + 1,
						}
						svrmsg.Afn0CPnF1.LoopData[i] = ld
					}
					// 电压
					for i := 0; i < x; i++ {
						svrmsg.Afn0CPnF1.LoopData[i].Voltage = gopsu.BcdBytes2Float64(d[j:j+2], 1, false)
						j += 2
					}
					// 电流
					for i := 0; i < x; i++ {
						svrmsg.Afn0CPnF1.LoopData[i].Current = gopsu.BcdBytes2Float64(d[j:j+3], 3, false)
						j += 3
					}
					// 填充有功功率数据
					for i := 0; i < x; i++ {
						svrmsg.Afn0CPnF1.LoopData[i].ActivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
						j += 3
					}
					// 填充无功功率数据
					for i := 0; i < x; i++ {
						svrmsg.Afn0CPnF1.LoopData[i].ReactivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
						j += 3
					}
					// 填充功率因数数据
					for i := 0; i < x; i++ {
						svrmsg.Afn0CPnF1.LoopData[i].PowerFactor = gopsu.BcdBytes2Float64(d[j:j+2], 1, false)
						j += 2
					}
					// 填充光控值
					for i := 0; i < x; i++ {
						svrmsg.Afn0CPnF1.LoopData[i].LuxValue = gopsu.BcdBytes2Float64(d[j:j+2], 1, false)
						j += 2
					}
				}
			}
		case 0x0d: // 请求历史数据
			switch uid.Pn {
			case 0:
				switch uid.Fn {
				case 2: // 模拟量历史数据曲线（进线）
					svrmsg.Afn0DP0F2 = &msgopen.Afn0D_P0_F2{}
					svrmsg.Afn0DP0F2.DtStart = gopsu.BcdDT2Stamp(d[j : j+5])
					j += 5
					svrmsg.Afn0DP0F2.DataDensity = int32(d[j])
					j++
					svrmsg.Afn0DP0F2.DataNum = int32(d[j])
					j++
					svrmsg.Afn0DP0F2.LoopNo = int32(d[j])
					j++
					// 填充所有结构
					svrmsg.Afn0DP0F2.PhaseAData = make([]*msgopen.Afn0D_P0_F2_Phase_Data, int(svrmsg.Afn0DP0F2.DataNum))
					svrmsg.Afn0DP0F2.PhaseBData = make([]*msgopen.Afn0D_P0_F2_Phase_Data, int(svrmsg.Afn0DP0F2.DataNum))
					svrmsg.Afn0DP0F2.PhaseCData = make([]*msgopen.Afn0D_P0_F2_Phase_Data, int(svrmsg.Afn0DP0F2.DataNum))
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						pda := &msgopen.Afn0D_P0_F2_Phase_Data{}
						pdb := &msgopen.Afn0D_P0_F2_Phase_Data{}
						pdc := &msgopen.Afn0D_P0_F2_Phase_Data{}
						svrmsg.Afn0DP0F2.PhaseAData[i] = pda
						svrmsg.Afn0DP0F2.PhaseBData[i] = pdb
						svrmsg.Afn0DP0F2.PhaseCData[i] = pdc
					}
					// 填充A相电压数据
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseAData[i].Voltage = gopsu.BcdBytes2Float64(d[j:j+2], 1, true)
						j += 2
					}
					// 填充B相电压
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseBData[i].Voltage = gopsu.BcdBytes2Float64(d[j:j+2], 1, true)
						j += 2
					}
					// 填充C相电压
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseCData[i].Voltage = gopsu.BcdBytes2Float64(d[j:j+2], 1, true)
						j += 2
					}
					// 填充A相电流
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseAData[i].Current = gopsu.BcdBytes2Float64(d[j:j+3], 3, false)
						j += 3
					}
					// 填充B相电流
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseCData[i].Current = gopsu.BcdBytes2Float64(d[j:j+3], 3, false)
						j += 3
					}
					// 填充C相电流
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseCData[i].Current = gopsu.BcdBytes2Float64(d[j:j+3], 3, false)
						j += 3
					}
					// 填充A相有功功率
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseAData[i].ActivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
						j += 3
					}
					// 填充B相有功功率
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseBData[i].ActivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
						j += 3
					}
					// 填充C相有功功率
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseCData[i].ActivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
						j += 3
					}
					// 填充A相无功功率
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseAData[i].ReactivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
						j += 3
					}
					// 填充B相无功功率
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseBData[i].ReactivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
						j += 3
					}
					// 填充C相无功功率
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseCData[i].ReactivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
						j += 3
					}
					// 填充A相功率因数
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseAData[i].PowerFactor = gopsu.BcdBytes2Float64(d[j:j+2], 1, false)
						j += 2
					}
					// 填充B相功率因数
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseBData[i].PowerFactor = gopsu.BcdBytes2Float64(d[j:j+2], 1, false)
						j += 2
					}
					// 填充C相功率因数
					for i := 0; i < int(svrmsg.Afn0DP0F2.DataNum); i++ {
						svrmsg.Afn0DP0F2.PhaseCData[i].PowerFactor = gopsu.BcdBytes2Float64(d[j:j+2], 1, false)
						j += 2
					}
				}
			default:
				switch uid.Fn {
				case 1: // 模拟量历史数据曲线（出线）
					svrmsg.Afn0DPnF1 = &msgopen.Afn0D_Pn_F1{}
					svrmsg.Afn0DPnF1.DtStart = gopsu.BcdDT2Stamp(d[j : j+5])
					j += 5
					svrmsg.Afn0DPnF1.DataDensity = int32(d[j])
					j++
					svrmsg.Afn0DPnF1.DataNum = int32(d[j])
					j++
					svrmsg.Afn0DPnF1.LoopNo = append(svrmsg.Afn0DPnF1.LoopNo, int32(d[j]))
					j++
					svrmsg.Afn0DPnF1.LoopData = make([]*msgopen.Afn0D_Pn_F1_Loop_Data, int(svrmsg.Afn0DPnF1.DataNum))
					for i := 0; i < int(svrmsg.Afn0DPnF1.DataNum); i++ {
						ld := &msgopen.Afn0D_Pn_F1_Loop_Data{}
						svrmsg.Afn0DPnF1.LoopData[i] = ld
					}
					// 填充电压数据
					for i := 0; i < int(svrmsg.Afn0DPnF1.DataNum); i++ {
						svrmsg.Afn0DPnF1.LoopData[i].Voltage = gopsu.BcdBytes2Float64(d[j:j+2], 1, true)
						j += 2
					}
					// 填充电流数据
					for i := 0; i < int(svrmsg.Afn0DPnF1.DataNum); i++ {
						svrmsg.Afn0DPnF1.LoopData[i].Current = gopsu.BcdBytes2Float64(d[j:j+3], 3, false)
						j += 3
					}
					// 填充有功功率数据
					for i := 0; i < int(svrmsg.Afn0DPnF1.DataNum); i++ {
						svrmsg.Afn0DPnF1.LoopData[i].ActivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
						j += 3
					}
					// 填充无功功率数据
					for i := 0; i < int(svrmsg.Afn0DPnF1.DataNum); i++ {
						svrmsg.Afn0DPnF1.LoopData[i].ReactivePower = gopsu.BcdBytes2Float64(d[j:j+3], 4, false)
						j += 3
					}
					// 填充功率因数数据
					for i := 0; i < int(svrmsg.Afn0DPnF1.DataNum); i++ {
						svrmsg.Afn0DPnF1.LoopData[i].PowerFactor = gopsu.BcdBytes2Float64(d[j:j+2], 1, false)
						j += 2
					}
					// 填充光控值
					for i := 0; i < int(svrmsg.Afn0DPnF1.DataNum); i++ {
						svrmsg.Afn0DPnF1.LoopData[i].LuxValue = gopsu.BcdBytes2Float64(d[j:j+2], 1, false)
						j += 2
					}
				case 3: // 漏电历史数据曲线
					svrmsg.Afn0DPnF3 = &msgopen.Afn0D_Pn_F3{}
					svrmsg.Afn0DPnF3.DtStart = gopsu.BcdDT2Stamp(d[j : j+5])
					j += 5
					svrmsg.Afn0DPnF3.DataDensity = int32(d[j])
					j++
					svrmsg.Afn0DPnF3.DataNum = int32(d[j])
					j++
					svrmsg.Afn0DPnF3.LoopNo = append(svrmsg.Afn0DPnF3.LoopNo, int32(d[j]))
					j++
					for i := 0; i < int(svrmsg.Afn0DPnF3.DataNum); i++ {
						svrmsg.Afn0DPnF3.LeakageCurrent = append(svrmsg.Afn0DPnF3.LeakageCurrent, gopsu.BcdBytes2Float64(d[j:j+3], 3, false))
						j += 3
					}
				}
			}
		case 0x0e: // 请求事件记录
			switch uid.Pn {
			case 0:
				switch uid.Fn {
				case 1, 2: // 重要/一般事件
					svrmsg.Afn0EP0F1 = &msgopen.Afn0E_P0_F1{}
					svrmsg.Afn0EP0F1.EcNow = int32(d[j])
					j++
					svrmsg.Afn0EP0F1.Pm = int32(d[j])
					j++
					svrmsg.Afn0EP0F1.Pn = int32(d[j])
					j++
					var x = int(svrmsg.Afn0EP0F1.Pn - svrmsg.Afn0EP0F1.Pm)
					if x < 0 {
						x = 256 + x
					}
					svrmsg.Afn0EP0F1.EventsData = make([]*msgopen.Afn0E_P0_F1_Events_Data, x)
					for i := 0; i < x; i++ { // 循环获取事件
						erc := &msgopen.Afn0E_P0_F1_Events_Data{}
						erc.EventId = int32(d[j])
						j += 4
						erc.EventTime = gopsu.BcdDT2Stamp(d[j : j+5])
						j += 5
						switch erc.EventId {
						case 4:
							erc.Erc04 = &msgopen.Afn0E_P0_F1_Erc04_Data{
								DiStatus: int32(d[j]),
								DiNo:     int32(d[j+1]),
							}
							j += 2
						case 5:
							erc.Erc05 = &msgopen.Afn0E_P0_F1_Erc05_Data{
								SwitchoutDo:     int32(d[j] ^ 1),
								SwitchoutNo:     int32(d[j+1]),
								SwitchoutSource: int32(d[j+2]),
							}
							j += 3
						case 13:
							erc.Erc13 = &msgopen.Afn0E_P0_F1_Erc13_Data{
								ReportType: int32(d[j]),
							}
							j++
						case 20:
							erc.Erc20 = &msgopen.Afn0E_P0_F1_Erc20_Data{
								ReportType:     int32(d[j]),
								LeakageNo:      int32(d[j+1]),
								LeakageLevel:   int32(d[j+2]),
								LeakageCurrent: gopsu.BcdBytes2Float64(d[j+3:j+6], 3, false),
							}
							j += 7
						case 21:
							erc.Erc21 = &msgopen.Afn0E_P0_F1_Erc20_Data{
								ReportType:     int32(d[j]),
								LeakageNo:      int32(d[j+1]),
								LeakageLevel:   4,
								LeakageCurrent: gopsu.BcdBytes2Float64(d[j+2:j+5], 3, false),
							}
							j += 6
						case 22:
							erc.Erc22 = &msgopen.Afn0E_P0_F1_Erc22_Data{
								ReportType: int32(d[j]),
								Phase:      int32(d[j+1]),
							}
							j += 2
						case 23:
							erc.Erc23 = &msgopen.Afn0E_P0_F1_Erc22_Data{
								ReportType: int32(d[j]),
								Phase:      int32(d[j+1]),
							}
							j += 2
						case 24:
							erc.Erc24 = &msgopen.Afn0E_P0_F1_Erc22_Data{
								ReportType: int32(d[j]),
								Phase:      int32(d[j+1]),
							}
							j += 2
						case 25:
							erc.Erc25 = &msgopen.Afn0E_P0_F1_Erc25_Data{
								ReportType: int32(d[j]),
								LoopNo:     int32(d[j+1]),
							}
							j += 2
						case 26:
							erc.Erc26 = &msgopen.Afn0E_P0_F1_Erc25_Data{
								ReportType: int32(d[j]),
								LoopNo:     int32(d[j+1]),
							}
							j += 2
						case 27:
							erc.Erc27 = &msgopen.Afn0E_P0_F1_Erc25_Data{
								ReportType: int32(d[j]),
								LoopNo:     int32(d[j+1]),
							}
							j += 2
						case 28:
							erc.Erc28 = &msgopen.Afn0E_P0_F1_Erc25_Data{
								ReportType: int32(d[j]),
								LoopNo:     int32(d[j+1]),
							}
							j += 2
						case 29:
							erc.Erc29 = &msgopen.Afn0E_P0_F1_Erc25_Data{
								ReportType: int32(d[j]),
								LoopNo:     int32(d[j+1]),
							}
							j += 2
						case 30:
							erc.Erc30 = &msgopen.Afn0E_P0_F1_Erc25_Data{
								ReportType: int32(d[j]),
								LoopNo:     int32(d[j+1]),
							}
							j += 2
						}
						svrmsg.Afn0EP0F1.EventsData[i] = erc
					}
				}
			default:
			}
		case 0x10: // 数据转发
			switch uid.Pn {
			case 0:
				switch uid.Fn {
				case 2: // 透明转发(有疑问)
				case 10: // 终端FTP升级结果
					svrmsg.Afn10P0F10 = &msgopen.Afn10_P0_F10{}
					svrmsg.Afn10P0F10.SoftwareVerOld = gopsu.TrimString(string(d[j : j+4]))
					j += 4
					svrmsg.Afn10P0F10.SoftwareDateOld = int32(gopsu.BcdBytes2Float64(d[j:j+3], 0, true))
					j += 3
					svrmsg.Afn10P0F10.SoftwareVerNew = gopsu.TrimString(string(d[j : j+4]))
					j += 4
					svrmsg.Afn10P0F10.SoftwareDateNew = int32(gopsu.BcdBytes2Float64(d[j:j+3], 0, true))
					j += 3
					svrmsg.Afn10P0F10.DtUpgrade = gopsu.BcdDT2Stamp(d[j : j+5])
					j += 5
				case 41: // 模块FTP升级结果
					svrmsg.Afn10P0F41 = &msgopen.Afn10_P0_F10{}
					svrmsg.Afn10P0F41.DevType = gopsu.TrimString(string(d[j : j+3]))
					j += 3
					svrmsg.Afn10P0F41.SoftwareVerOld = gopsu.TrimString(string(d[j : j+4]))
					j += 4
					svrmsg.Afn10P0F41.SoftwareDateOld = int32(gopsu.BcdBytes2Float64(d[j:j+3], 0, true))
					j += 3
					svrmsg.Afn10P0F41.SoftwareVerNew = gopsu.TrimString(string(d[j : j+4]))
					j += 4
					svrmsg.Afn10P0F41.SoftwareDateNew = int32(gopsu.BcdBytes2Float64(d[j:j+3], 0, true))
					j += 3
					svrmsg.Afn10P0F41.DtUpgrade = gopsu.BcdDT2Stamp(d[j : j+5])
					j += 5
				}
			default:
			}
		}
	}
	// 设备需要应答
	if con == 1 {
		switch afn {
		case 0x02: // 登录,心跳
			var ff = &Fwd{
				DataCmd:  fmt.Sprintf("gb.open.%02x%02x", fun, afn),
				DataType: DataTypeBytes,
				DataDst:  fmt.Sprintf("gb-open-%d-%s", f.Addr, dp.AreaCode),
				DstType:  SockTml,
				DataMsg:  dp.BuildCommand(dAns, f.Addr, 0, 11, 0, 1, 0, 0, int32(seq), dp.AreaCode),
				Tra:      TraDirect,
				Job:      JobSend,
				Src:      gopsu.Bytes2String(d, "-"),
				Addr:     f.Addr,
			}
			lstf = append(lstf, ff)
		case 0x0c, 0x10: // 请求实时数据,数据转发
			var ff = &Fwd{
				DataCmd:  fmt.Sprintf("gb.open.%02x%02x", fun, afn),
				DataType: DataTypeBytes,
				DataDst:  fmt.Sprintf("gb-open-%d-%s", f.Addr, dp.AreaCode),
				DstType:  SockTml,
				DataMsg:  dp.BuildCommand(dAns, f.Addr, 0, 8, 0, 1, int32(afn), 0, int32(seq), dp.AreaCode),
				Tra:      TraDirect,
				Job:      JobSend,
				DataSP:   SendLevelHigh,
				Addr:     f.Addr,
			}
			lstf = append(lstf, ff)
		}
	}
	if len(f.DataCmd) > 0 {
		b, _ := svrmsg.Marshal()
		f.DataMsg = b
		lstf = append(lstf, f)
	}

	return lstf
}
