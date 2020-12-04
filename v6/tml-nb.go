package v6

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/xyzj/gopsu"
	msgnb "github.com/xyzj/proto/msgnb"
)

// ClassifyTmlDataNB NB数据解析
// Args:
// 	rawdata: base64原始数据
// Return:
// 	r: 处理反馈结果
func ClassifyTmlDataNB(rawdata, deviceID string, imei, at int64, dataflag int32) (r *Rtb) {
	r = &Rtb{}
	d, err := base64.StdEncoding.DecodeString(rawdata)
	if err != nil {
		return r
	}
	return ClassifyTmlData(d, imei, at, deviceID, dataflag)
}

// ClassifyTmlData 分类数据解析
// Args:
// 	d: 原始数据
// 	ip：数据来源ip
// 	port：数据服务端口
//  checkrc：是否进行数据校验
// Return:
// 	r: 处理反馈结果
func ClassifyTmlData(d []byte, imei, at int64, deviceID string, dataflag int32) (r *Rtb) {
	r = &Rtb{}
	defer func() {
		if ex := recover(); ex != nil {
			r.Src = gopsu.Bytes2String(d, "-")
			r.Ex = fmt.Sprintf("%+v", errors.WithStack(ex.(error)))
		}
	}()
LOOP:
	if !bytes.ContainsAny(d, "~{>h^"+string([]byte{0xff})) ||
		(len(d) < 3 && bytes.ContainsAny(d, "<")) || len(d) < 3 {
		return r
	}
	for k, v := range d {
		if len(d)-k <= 3 {
			return r
		}
		switch v {
		case 0xff: // 升级指令
			if len(d[k:]) < 9 {
				r.Ex = fmt.Sprintf("Insufficient data length. %s", gopsu.Bytes2String(d[k:], "-"))
				r.Unfinish = d
				d = []byte{}
				goto LOOP
			}
			if d[k+1] == 0xfe && bytes.Contains([]byte{0x81, 0x85, 0x86, 0x87, 0x88}, []byte{d[k+4]}) {
				l := int(d[k+2]) + int(d[k+3])*256
				r.Do = append(r.Do, dataNBUp(d[k:k+l+6], imei, at, deviceID, dataflag)...)
				d = d[k+l+6:]
				goto LOOP
			}
		case 0x68: // 常规指令
			if len(d[k:]) < 12 {
				r.Ex = fmt.Sprintf("Insufficient data length. %s", gopsu.Bytes2String(d[k:], "-"))
				r.Unfinish = d
				d = []byte{}
				goto LOOP
			}
			// udp单灯
			lMru := int(d[k+9])
			if d[k+7] == 0x68 && d[k+lMru+11] == 0x16 &&
				bytes.Contains([]byte{0x91, 0xd3, 0x93, 0x81, 0x9c}, []byte{d[k+8]}) {
				r.Do = append(r.Do, dataNB(d[k:k+lMru+12], imei, at, deviceID, dataflag)...)
				d = d[k+lMru+12:]
				goto LOOP
			}
		}
	}
	return r
}

// dataNBUp nb升级协议处理
// Args:
// 	d: 原始数据
// 	imei：设备imei
//  at:数据时间
//  deviceID: 设备注册后的平台id
// Return:
// 	lstf: 处理反馈结果
func dataNBUp(d []byte, imei, at int64, deviceID string, dataflag int32) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      1,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}
	f.Addr = imei
	if !gopsu.CheckCrc16VB(d) {
		f.Ex = "nbslu upgrade data validation fails"
		lstf = append(lstf, f)
		return lstf
	}
	f.DataDst = fmt.Sprintf("wlst-nbupg-%d", f.Addr)
	svrmsg := initMsgNB("", deviceID, int64(f.Addr), imei, at, dataflag)
	svrmsg.Seq = int32(d[5])
	svrmsg.Status = int32(d[6])
	l := int(d[2]) + int(d[3])*256
	switch d[4] {
	case 0x81: // 升级成功上报
		svrmsg.NbSluFf01 = &msgnb.NBSlu_FF01{}
		f.DataCmd = "wlst.nbupg.fe01"
		if svrmsg.Status > 0 {
			break
		}
		var s string
		for _, v := range d[7 : l+4-1] {
			if v == 0 && svrmsg.NbSluFf01.OldVer == "" {
				svrmsg.NbSluFf01.OldVer = s
				s = ""
			}
			if v == 0 {
				continue
			}
			s += string(v)
		}
		svrmsg.NbSluFf01.NewVer = s
	case 0x85: // 读取版本
		svrmsg.NbSluFf05 = &msgnb.NBSlu_FF05{}
		f.DataCmd = "wlst.nbupg.fe05"
		if svrmsg.Status > 0 {
			break
		}
		svrmsg.NbSluFf05.Ver = string(d[7 : l+4-1])
	case 0x86: // 升级准备
		f.DataCmd = "wlst.nbupg.fe06"
	case 0x87: // 查询包状态
		svrmsg.NbSluFf07 = &msgnb.NBSlu_FF07{}
		f.DataCmd = "wlst.nbupg.fe07"
		if svrmsg.Status != 0 && svrmsg.Status != 8 {
			break
		}
		svrmsg.NbSluFf07.DatapackTotal = int32(d[7]) + int32(d[8])*256
		var s string
		for _, v := range d[9 : l+4] {
			s = fmt.Sprintf("%08b", v) + s
		}
		s = gopsu.ReverseString(s)
		for k, v := range s {
			if int32(k) >= svrmsg.NbSluFf07.DatapackTotal {
				break
			}
			svrmsg.NbSluFf07.DatapackStatus = append(svrmsg.NbSluFf07.DatapackStatus, v-48)
		}
	case 0x88: // 数据包应答
		f.DataCmd = "wlst.nbupg.fe08"
	default:
		f.Ex = "Unhandled nbslu upgrade data"
		lstf = append(lstf, f)
		return lstf
	}
	if len(f.DataCmd) > 0 {
		svrmsg.DataCmd = f.DataCmd
		f.DataMsg = CodePb2NB(svrmsg)
		lstf = append(lstf, f)
	}

	return lstf
}

// 处理NB数据
// Args:
// 	d: 原始数据
// 	imei：设备imei
//  at:数据时间
//  deviceID: 设备注册后的平台id
// Return:
// 	lstf: 处理反馈结果
func dataNB(d []byte, imei, at int64, deviceID string, dataflag int32) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      1,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}

	var xaddr string
	for i := 6; i > 0; i-- {
		xaddr += fmt.Sprintf("%02x", d[i])
	}
	f.Addr = int64(gopsu.String2Int64(xaddr, 10))

	svrmsg := initMsgNB("", deviceID, int64(f.Addr), imei, at, dataflag)
	switch d[8] {
	case 0x9c:
		l := d[9]
		dd := d[10 : 10+l]
		if !gopsu.CheckCrc16VB(dd) {
			f.Ex = "nbslu data validation fails"
			lstf = append(lstf, f)
			return lstf
		}
		cmd := dd[4]
		if dd[1] <= 4 {
			f.Ex = fmt.Sprintf("nbslu data length error ")
			lstf = append(lstf, f)
			return lstf
		}
		switch cmd {
		case 0xa3: // 单灯设置
			f.DataCmd = "wlst.vslu.fa00"
			svrmsg.DataType = 3
			svrmsg.SluitemConfig = &msgnb.SluitemConfig{}
			svrmsg.SluitemConfig.DataMark = &msgnb.SluitemConfig_DataMark{}
			svrmsg.SluitemConfig.SetMark = &msgnb.SluitemConfig_SetMark{}
			svrmsg.SluitemConfig.SluitemPara = &msgnb.SluitemConfig_SluitemPara{}
			svrmsg.SluitemConfig.SluitemVer = &msgnb.SluitemConfig_SluitemVer{}
			svrmsg.SluitemConfig.SluitemSunriseset = &msgnb.SluitemConfig_SluitemSunriseset{}
			svrmsg.SluitemConfig.SluitemRuntime = []*msgnb.SluitemConfig_SluitemRuntime{}
			setMark := fmt.Sprintf("%08b%08b", dd[6], dd[5])
			readMark := fmt.Sprintf("%08b%08b", dd[8], dd[7])
			//var setResult string
			var readResult string
			if setMark[15] == 49 {
				//setResult = fmt.Sprintf("%08b%08b", dd[10], dd[9])
				readResult = fmt.Sprintf("%08b%08b", dd[12], dd[11])
			} else {
				//setResult = fmt.Sprintf("%08b%08b", 0xff, 0xff)
				readResult = fmt.Sprintf("1%08b%08b", 0xff, 0xff)
			}
			if gopsu.String2Int64(readMark[3:], 2) == 0 {
				if setMark[14:15] == "1" { // 设置时钟
					f.DataCmd = "wlst.vslu.f100"
					svrmsg.SluitemConfig.SetMark = &msgnb.SluitemConfig_SetMark{
						SetTimer: 1,
					}
				}
				if setMark[13:14] == "1" { // 设置参数
					f.DataCmd = "wlst.vslu.f200"
					svrmsg.SluitemConfig.SetMark = &msgnb.SluitemConfig_SetMark{
						SetArgs: 1,
					}
				}
				if setMark[11:12] == "1" { // 设置分组
					f.DataCmd = "wlst.vslu.f200"
					svrmsg.SluitemConfig.SetMark = &msgnb.SluitemConfig_SetMark{
						SetArgs: 1,
					}
				}
				if setMark[9:10] == "1" { // 复位
					f.DataCmd = "wlst.vslu.ef00"
					svrmsg.SluitemConfig.SetMark = &msgnb.SluitemConfig_SetMark{
						SetReset: 1,
					}
				}
				if setMark[6:7] == "1" { // 时间设置
					f.DataCmd = "wlst.vslu.fc00"
					svrmsg.DataType = 2
					svrmsg.SluitemConfig.SetMark = &msgnb.SluitemConfig_SetMark{
						SetTimetable: 1,
					}
				}
			} else {
				svrmsg.SluitemConfig.Status = 1
				loopCount := int(gopsu.String2Int32(readMark[:3], 2) + 1)
				svrmsg.SluitemConfig.LoopCount = int32(loopCount)
				j := 9
				if len(readResult) == 16 {
					j += 4
				}
				if readMark[14:15] == "1" && readResult[14] == 49 { // 读取时钟
					svrmsg.SluitemConfig.DataMark.ReadTimer = 1
					svrmsg.SluitemConfig.SluitemTime = gopsu.Time2Stamp(fmt.Sprintf("20%02d-%02d-%02d %02d:%02d:%02d", dd[j], dd[j+1], dd[j+2], dd[j+3], dd[j+4], dd[j+5]))
					j += 6
				}
				if readMark[13:14] == "1" && readResult[13] == 49 { // 读取运行参数
					svrmsg.SluitemConfig.DataMark.ReadArgs = 1
					x, _ := strconv.ParseFloat(fmt.Sprintf("%d.%02d", dd[j], int(dd[j+1])), 10)
					svrmsg.SluitemConfig.SluitemPara.Longitude = x
					j += 2
					x, _ = strconv.ParseFloat(fmt.Sprintf("%d.%02d", dd[j], int(dd[j+1])), 10)
					svrmsg.SluitemConfig.SluitemPara.Latitude = x
					j += 2
					j += 2
					s := fmt.Sprintf("%08b", dd[j])
					y, _ := strconv.ParseInt(s[:4], 2, 0)
					if y == 5 {
						svrmsg.SluitemConfig.SluitemPara.SluitemEnableAlarm = 1
					} else {
						svrmsg.SluitemConfig.SluitemPara.SluitemEnableAlarm = 0
					}
					y, _ = strconv.ParseInt(s[4:], 2, 0)
					if y == 5 {
						svrmsg.SluitemConfig.SluitemPara.SluitemStatus = 1
					} else {
						svrmsg.SluitemConfig.SluitemPara.SluitemStatus = 0
					}
					j++
					s = fmt.Sprintf("%08b", dd[j])
					for i := 0; i < loopCount; i++ {
						if s[8-(i+1):8-i] == "0" {
							svrmsg.SluitemConfig.SluitemPara.SluitemPowerTurnon = append(svrmsg.SluitemConfig.SluitemPara.SluitemPowerTurnon, 1)
						} else {
							svrmsg.SluitemConfig.SluitemPara.SluitemPowerTurnon = append(svrmsg.SluitemConfig.SluitemPara.SluitemPowerTurnon, 0)
						}
					}
					j++
					s = fmt.Sprintf("%08b", dd[j])
					for i := 7; i >= 4; i-- {
						svrmsg.SluitemConfig.SluitemPara.SluitemReverseDimming = append(svrmsg.SluitemConfig.SluitemPara.SluitemReverseDimming, int32(s[i]-48))
					}
					j++
					s = fmt.Sprintf("%08b%08b", dd[j+1], dd[j])
					for i := 0; i < loopCount; i++ {
						y, _ = strconv.ParseInt(s[16-(i*4+4):16-i*4], 2, 0)
						svrmsg.SluitemConfig.SluitemPara.RatedPower = append(svrmsg.SluitemConfig.SluitemPara.RatedPower, int32(y))
					}
					j += 2
					s = fmt.Sprintf("%08b", dd[j])
					svrmsg.SluitemConfig.SluitemPara.UplinkReply = gopsu.String2Int32(s[:1], 2)
					svrmsg.SluitemConfig.SluitemPara.UplinkTimer = gopsu.String2Int32(s[1:], 2) * 5
					if svrmsg.SluitemConfig.SluitemPara.UplinkTimer == 0 {
						svrmsg.SluitemConfig.SluitemPara.UplinkTimer = 30
					}
					j++
				}
				if readMark[10:11] == "1" && readResult[10] == 49 { // 读取版本
					svrmsg.SluitemConfig.DataMark.ReadVer = 1
					s := fmt.Sprintf("%08b%08b", dd[j+1], dd[j])
					svrmsg.SluitemConfig.SluitemVer.SluitemLoop = gopsu.String2Int32(s[13:16], 2) + 1
					svrmsg.SluitemConfig.SluitemVer.EnergySaving = gopsu.String2Int32(s[10:13], 2)
					svrmsg.SluitemConfig.SluitemVer.ElectricLeakageModule = gopsu.String2Int32(s[9:10], 2)
					svrmsg.SluitemConfig.SluitemVer.TemperatureModule = gopsu.String2Int32(s[8:9], 2)
					svrmsg.SluitemConfig.SluitemVer.TimerModule = gopsu.String2Int32(s[7:8], 2)
					x, _ := strconv.ParseInt(s[:4], 2, 0)
					switch x {
					case 0:
						svrmsg.SluitemConfig.SluitemVer.SluitemType = "未知"
					case 1:
						svrmsg.SluitemConfig.SluitemVer.SluitemType = "wj2190"
					case 2:
						svrmsg.SluitemConfig.SluitemVer.SluitemType = "wj2090j"
					case 3:
						svrmsg.SluitemConfig.SluitemVer.SluitemType = "wj5090"
					case 4:
						svrmsg.SluitemConfig.SluitemVer.SluitemType = "wj2090k"
					case 5:
						svrmsg.SluitemConfig.SluitemVer.SluitemType = "wj2290"
					case 6:
						svrmsg.SluitemConfig.SluitemVer.SluitemType = "wj2080c"
					case 8:
						svrmsg.SluitemConfig.SluitemVer.SluitemType = "wj2080d"
					case 9:
						svrmsg.SluitemConfig.SluitemVer.SluitemType = "wj4090b"
					case 10:
						svrmsg.SluitemConfig.SluitemVer.SluitemType = "wj2090l"
					case 12:
						svrmsg.SluitemConfig.SluitemVer.SluitemType = "wj2090m"
					case 14:
						svrmsg.SluitemConfig.SluitemVer.SluitemType = "wj4090a"
					default:
						svrmsg.SluitemConfig.SluitemVer.SluitemType = "未知"
					}
					j += 2
					svrmsg.SluitemConfig.SluitemVer.Ver = string(dd[j : j+20])
					j += 20
				}
				if readMark[9:10] == "1" && readResult[9] == 49 { // 读取当天日出日落
					svrmsg.SluitemConfig.DataMark.ReadSunriseset = 1
					svrmsg.SluitemConfig.SluitemSunriseset.Sunrise = int32(dd[j])*60 + int32(dd[j+1])
					j += 2
					svrmsg.SluitemConfig.SluitemSunriseset.Sunset = int32(dd[j])*60 + int32(dd[j+1])
					j += 2
				}
				if readMark[6:7] == "1" && readResult[6] == 49 { // 读取本地参数（新）
					svrmsg.SluitemConfig.DataMark.ReadTimetable = 1
					s := fmt.Sprintf("%08b", dd[j])        // 后续条数
					c := int(gopsu.String2Int32(s[2:], 2)) // 条数
					// 加入是否有后续数据返回
					// if s[0] == 49 {
					// 	svrmsg.SluitemConfig.DataContinue = 1
					// }
					j++
					mtype := fmt.Sprintf("%08b%08b%08b%08b", dd[j+3], dd[j+2], dd[j+1], dd[j]) // 数据类型4字节
					j += 4
					for i := 0; i < c; i++ {
						cr := &msgnb.SluitemConfig_SluitemRuntime{}
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
						svrmsg.SluitemConfig.SluitemRuntime = append(svrmsg.SluitemConfig.SluitemRuntime, cr)
					}
				}
				if readMark[5:6] == "1" && readResult[5] == 49 { // 选测（新）
					f.DataCmd = "wlst.vslu.b900"
					svrmsg.DataType = 1
					svrmsg.SluitemData = &msgnb.SluitemData{}
					svrmsg.SluitemData.ModelInfo = &msgnb.SluitemData_ModelInfo{}
					svrmsg.SluitemData.SluitemStatus = &msgnb.SluitemData_SluitemStatus{}
					svrmsg.SluitemData.TimeFault = &msgnb.SluitemData_TimeFault{}
					svrmsg.SluitemData.SluitemPara = &msgnb.SluitemData_SluitemPara{}

					svrmsg.SluitemData.DateTime = time.Now().Unix()
					mi := &msgnb.SluitemData_ModelInfo{}
					mi.Model = 9
					mi.SluitemType = "NBV0.1Old"
					mi.UseLoop = int32(loopCount)
					svrmsg.SluitemData.ModelInfo = mi

					// 回路数据（电压、电流、有功、无功、视在、电量、运行时间、灯状态）
					cbd := &msgnb.SluitemData{}
					for k := 0; k < 4; k++ {
						ld := &msgnb.SluitemData_LightData{}
						ls := &msgnb.SluitemData_LightStatus{}
						if k >= loopCount {
							ld.Voltage = float64(0)
							ld.Current = float64(0)
							ld.ActivePower = float64(0)
							ld.Electricity = float64(0)
							ld.ActiveTime = float64(0)

							ls.Leakage = 0
							ls.Fault = 0
							ls.WorkingOn = 0

							ld.LightStatus = ls
						} else {
							ld.Voltage = (float64(dd[j+2*k]) + float64(dd[j+1+2*k])*256) / 100
							ld.Current = (float64(dd[j+2*loopCount+2*k]) + float64(dd[j+1+2*loopCount+2*k])*256) / 100
							ld.ActivePower = (float64(dd[j+4*loopCount+2*k]) + float64(dd[j+1+4*loopCount+2*k])*256) / 10
							ld.Electricity = (float64(dd[j+6*loopCount+2*k]) + float64(dd[j+1+6*loopCount+2*k])*256) / 10
							ld.ActiveTime = float64(dd[j+8*loopCount+3*k]) + float64(dd[j+1+8*loopCount+3*k])*256 + float64(dd[j+2+8*loopCount+3*k])*256*256

							m := fmt.Sprintf("%08b", dd[j+11*loopCount+k])
							ls.Leakage = gopsu.String2Int32(m[2:3], 2)
							ls.Fault = gopsu.String2Int32(m[3:6], 2)
							ls.WorkingOn = gopsu.String2Int32(m[6:8], 2)

							ld.LightStatus = ls
						}
						cbd.LightData = append(cbd.LightData, ld)
					}
					j += 12 * loopCount

					// 漏电流 控制器状态 时钟故障 自复位次数
					svrmsg.SluitemData.LeakageCurrent = float64(dd[j]) / 100
					j++
					m := fmt.Sprintf("%08b", dd[j])
					svrmsg.SluitemData.SluitemStatus.FlashFault = gopsu.String2Int32(m[6:7], 2)
					svrmsg.SluitemData.SluitemStatus.EnableAlarm = gopsu.String2Int32(m[4:5], 2)
					j++
					m = fmt.Sprintf("%08b", dd[j])
					svrmsg.SluitemData.TimeFault.ClockFault = gopsu.String2Int32(m[7:8], 2)
					svrmsg.SluitemData.TimeFault.ClockOutFault = gopsu.String2Int32(m[6:7], 2)
					svrmsg.SluitemData.TimeFault.ClockOutAlarm = gopsu.String2Int32(m[5:6], 2)
					j++
					svrmsg.SluitemData.ResetCount = int32(dd[j])
					j++
					j++
					// 回路数据（节能档位）
					x1 := fmt.Sprintf("%08b%08b", dd[j], dd[j+1])
					x2 := fmt.Sprintf("%08b%08b", dd[j+2], dd[j+3])
					for k := range cbd.LightData {
						cbd.LightData[k].PowerLevel = gopsu.String2Int32(fmt.Sprintf("%d%d", gopsu.String2Int32(x1[4*k:4+4*k], 2), gopsu.String2Int32(x2[4*k:4+4*k], 2)), 10)
					}
					j += loopCount
					svrmsg.SluitemData.LightData = cbd.LightData
				}
			}
		case 0xb9: // 控制器主报（仅NB）
			f.DataCmd = "wlst.vslu.b900"
			svrmsg.DataType = 1
			svrmsg.SluitemData = &msgnb.SluitemData{}
			svrmsg.SluitemData.ModelInfo = &msgnb.SluitemData_ModelInfo{}
			svrmsg.SluitemData.SluitemStatus = &msgnb.SluitemData_SluitemStatus{}
			svrmsg.SluitemData.TimeFault = &msgnb.SluitemData_TimeFault{}
			svrmsg.SluitemData.SluitemPara = &msgnb.SluitemData_SluitemPara{}
			// 2位地址
			repcid := int32(d[12]) + int32(d[13])*256
			// 序号
			svrmsg.SluitemData.CmdIdx = int32(d[15])
			// 型号
			mi := &msgnb.SluitemData_ModelInfo{}
			j := 16
			m := fmt.Sprintf("%08b%08b", d[j+1], d[j])
			j += 2
			mi.Model = gopsu.String2Int32(m[:4], 2)
			switch mi.Model {
			case 0:
				mi.SluitemType = "NBV0.2"
			case 9:
				mi.SluitemType = "NBV0.1"
			default:
				mi.SluitemType = "未知"
			}
			mi.HasTimer = gopsu.String2Int32(m[7:8], 2)
			mi.HasTemperature = gopsu.String2Int32(m[8:9], 2)
			mi.HasLeakage = gopsu.String2Int32(m[9:10], 2)
			mi.PowerSaving = gopsu.String2Int32(m[10:13], 2)
			mi.SluitemLoop = gopsu.String2Int32(m[13:16], 2) + 1
			mi.UseLoop = gopsu.String2Int32(m[4:7], 2) + 1
			svrmsg.SluitemData.ModelInfo = mi

			// 回路数据（电压、电流、有功、无功、视在、电量、运行时间、灯状态）
			cbd := &msgnb.SluitemData{}
			for k := 0; k < 4; k++ {
				ld := &msgnb.SluitemData_LightData{}
				ls := &msgnb.SluitemData_LightStatus{}

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
			svrmsg.SluitemData.LeakageCurrent = float64(d[j]) / 100
			j++
			m = fmt.Sprintf("%08b", d[j])
			svrmsg.SluitemData.SluitemStatus.FlashFault = gopsu.String2Int32(m[6:7], 2)
			svrmsg.SluitemData.SluitemStatus.EnableAlarm = gopsu.String2Int32(m[4:5], 2)
			j++
			m = fmt.Sprintf("%08b", d[j])
			svrmsg.SluitemData.TimeFault.ClockFault = gopsu.String2Int32(m[7:8], 2)
			svrmsg.SluitemData.TimeFault.ClockOutFault = gopsu.String2Int32(m[6:7], 2)
			svrmsg.SluitemData.TimeFault.ClockOutAlarm = gopsu.String2Int32(m[5:6], 2)
			j++
			svrmsg.SluitemData.ResetCount = int32(d[j])
			j++

			// 回路数据（节能档位）
			for k := range cbd.LightData {
				cbd.LightData[k].PowerLevel = int32(d[j+k])
			}
			j += 4

			// 时间
			t := fmt.Sprintf("20%02d-%02d-%02d %02d:%02d:%02d", int32(d[j]), int32(d[j+1]), int32(d[j+2]), int32(d[j+3]), int32(d[j+4]), int32(d[j+5]))
			svrmsg.SluitemData.DateTime = gopsu.Time2Stamp(t)
			j += 6

			// 运行参数(经纬度 投停运)
			svrmsg.SluitemData.SluitemPara.Longitude = float64(d[j]) + float64(d[j+1])/100 + float64(d[j+2])/10000 + float64(d[j+3])/1000000
			j += 4
			svrmsg.SluitemData.SluitemPara.Latitude = float64(d[j]) + float64(d[j+1])/100 + float64(d[j+2])/10000 + float64(d[j+3])/1000000
			j += 4
			m = fmt.Sprintf("%02x", d[j])
			if gopsu.String2Int32(m[:1], 10) == 5 {
				svrmsg.SluitemData.SluitemPara.HasEnableAlarm = 1
			} else if gopsu.String2Int32(m[:1], 10) == 10 {
				svrmsg.SluitemData.SluitemPara.HasEnableAlarm = 0
			}
			if gopsu.String2Int32(m[1:2], 10) == 5 {
				svrmsg.SluitemData.SluitemPara.IsRunning = 1
			} else if gopsu.String2Int32(m[1:2], 10) == 10 {
				svrmsg.SluitemData.SluitemPara.IsRunning = 0
			}
			j++

			// 回路数据（控制器上电开灯 额定功率）
			m = fmt.Sprintf("%08b", d[j])
			for k := range m[4:8] {
				if gopsu.String2Int32(m[7-k:8-k], 2) == 0 {
					cbd.LightData[k].SluitemPowerTurnon = 1
				} else {
					cbd.LightData[k].SluitemPowerTurnon = 0
				}
			}
			j++
			for k := range cbd.LightData {
				cbd.LightData[k].RatedPower = int32(d[j+2*k]) + int32(d[j+1+2*k])*256
			}
			j += 8

			// 运行参数(主报参数)
			m = fmt.Sprintf("%08b", d[j])
			repflg := gopsu.String2Int32(m[:1], 2)
			svrmsg.SluitemData.SluitemPara.UplinkReply = repflg
			svrmsg.SluitemData.SluitemPara.AlarmInterval = gopsu.String2Int32(m[1:], 2) * 5
			if svrmsg.SluitemData.SluitemPara.AlarmInterval == 0 {
				svrmsg.SluitemData.SluitemPara.AlarmInterval = 30
			}
			j++

			// 调试信息
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			if gopsu.String2Int64(m[:1], 2) == 0 {
				svrmsg.SluitemData.Rsrp = gopsu.String2Int64(m[1:], 2)
			} else {
				svrmsg.SluitemData.Rsrp = 0 - gopsu.String2Int64(m[1:], 2)
			}
			j += 4
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			if gopsu.String2Int64(m[:1], 2) == 0 {
				svrmsg.SluitemData.Rssi = gopsu.String2Int64(m[1:], 2)
			} else {
				svrmsg.SluitemData.Rssi = 0 - gopsu.String2Int64(m[1:], 2)
			}
			j += 4
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			svrmsg.SluitemData.Snr = gopsu.String2Int64(m, 2)
			j += 4
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			svrmsg.SluitemData.Pci = gopsu.String2Int64(m, 2)
			j += 4
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			if gopsu.String2Int64(m[:1], 2) == 0 {
				svrmsg.SluitemData.Rsrq = gopsu.String2Int64(m[1:], 2)
			} else {
				svrmsg.SluitemData.Rsrq = 0 - gopsu.String2Int64(m[1:], 2)
			}
			j += 4
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			if gopsu.String2Int64(m[:1], 2) == 0 {
				svrmsg.SluitemData.Txpower = gopsu.String2Int64(m[1:], 2)
			} else {
				svrmsg.SluitemData.Txpower = 0 - gopsu.String2Int64(m[1:], 2)
			}
			j += 4
			m = fmt.Sprintf("%08b%08b%08b%08b", d[j+3], d[j+2], d[j+1], d[j])
			svrmsg.SluitemData.Earfcn = gopsu.String2Int64(m, 2)
			j += 4
			svrmsg.SluitemData.Ecl = int32(d[j])
			j++
			svrmsg.SluitemData.Csq = int32(d[j])
			j++
			svrmsg.SluitemData.Reson = int32(d[j])
			j++
			svrmsg.SluitemData.Retry = int32(d[j]) + int32(d[j+1])*256
			j += 2

			// 日出日落时间
			svrmsg.SluitemData.Sunrise = int32(d[j])*60 + int32(d[j+1])
			j += 2
			svrmsg.SluitemData.Sunset = int32(d[j])*60 + int32(d[j+1])
			j += 2

			svrmsg.SluitemData.LightData = cbd.LightData

			if repflg == 1 && svrmsg.SluitemData.Reson != 0 {
				sendstr := DoCommand(1, 1, 1, f.Addr, repcid, "wlst.vslu.3900", []byte{d[15]}, 1, 1)
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
				lstf = append(lstf, ff)
			}
		case 0xb7: // 登录信息数据主报
			svrmsg.DataType = 4
			f.DataCmd = "wlst.vslu.b700"
			svrmsg.NbSlu_3700 = &msgnb.NBSlu_3700{}
			// 2位地址
			j := 2
			repcid := int32(dd[j]) + int32(dd[j+1])*256
			j += 3
			// 序号
			svrmsg.NbSlu_3700.CmdIdx = int32(dd[j])
			j++
			svrmsg.NbSlu_3700.Imei = string(dd[6:21])
			j += 15
			svrmsg.NbSlu_3700.Imsi = string(dd[21:36])
			j += 15
			svrmsg.NbSlu_3700.Iccid = string(dd[36:56])
			j += 20
			svrmsg.NbSlu_3700.Band = int32(dd[56])
			j++
			m := fmt.Sprintf("%08b%08b%08b%08b", dd[j+3], dd[j+2], dd[j+1], dd[j])
			if gopsu.String2Int64(m[:1], 2) == 0 {
				svrmsg.NbSlu_3700.Rsrp = gopsu.String2Int64(m[1:], 2)
			} else {
				svrmsg.NbSlu_3700.Rsrp = 0 - gopsu.String2Int64(m[1:], 2)
			}
			j += 4
			m = fmt.Sprintf("%08b%08b%08b%08b", dd[j+3], dd[j+2], dd[j+1], dd[j])
			if gopsu.String2Int64(m[:1], 2) == 0 {
				svrmsg.NbSlu_3700.Snr = gopsu.String2Int64(m[1:], 2)
			} else {
				svrmsg.NbSlu_3700.Snr = 0 - gopsu.String2Int64(m[1:], 2)
			}

			sendstr := DoCommand(1, 1, 1, f.Addr, repcid, "wlst.vslu.3700", []byte{d[6]}, 1, 1)
			ff := &Fwd{
				Addr:     f.Addr,
				DataCmd:  "wlst.vslu.3700",
				DataType: DataTypeBytes,
				DataPT:   1000,
				DataDst:  fmt.Sprintf("wlst-nbslu-%d", f.Addr),
				DstType:  SockTml,
				Tra:      TraDirect,
				Job:      JobSend,
				DataMsg:  sendstr,
			}
			lstf = append(lstf, ff)

		case 0x94: // 时间设置应答
			svrmsg.DataType = 4
			f.DataCmd = "wlst.vslu.1400"
			svrmsg.NbSlu_1400 = &msgnb.NBSlu_1400{}
			// 序号
			j := 5
			svrmsg.NbSlu_1400.CmdIdx = int32(dd[j])
			j++
			svrmsg.NbSlu_1400.Status = int32(dd[j])
		case 0x95: // 读取时钟
			svrmsg.DataType = 4
			f.DataCmd = "wlst.vslu.1500"
			svrmsg.NbSlu_1400 = &msgnb.NBSlu_1400{}
			// 序号d
			j := 5
			svrmsg.NbSlu_1400.CmdIdx = int32(dd[j])
			j++
			svrmsg.NbSlu_1400.SluitemTime = gopsu.Time2Stamp(fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", int32(dd[j])+int32(dd[j+1])*256, dd[j+2], dd[j+3], dd[j+4], dd[j+5], dd[j+6]))
			j += 7
			svrmsg.NbSlu_1400.Week = int32(dd[j])
		case 0xd1: // 读取版本
			svrmsg.DataType = 9
			f.DataCmd = "wlst.vslu.5100"
			svrmsg.NbSlu_5100 = &msgnb.NBSlu_5100{}
			// 序号d
			j := 5
			svrmsg.NbSlu_5100.CmdIdx = int32(dd[j])
			j++
			svrmsg.NbSlu_5100.Ver = string(dd[j : j+20])
		case 0xd2: // 设置运行参数应答
			svrmsg.DataType = 10
			f.DataCmd = "wlst.vslu.5200"
			svrmsg.NbSlu_5200 = &msgnb.NBSlu_5200{}
			// 序号d
			j := 5
			svrmsg.NbSlu_5200.CmdIdx = int32(dd[j])
			j++
			svrmsg.NbSlu_5200.Status = int32(dd[j])
		case 0xd3: // 读取运行参数
			svrmsg.DataType = 10
			f.DataCmd = "wlst.vslu.5300"
			svrmsg.NbSlu_5200 = &msgnb.NBSlu_5200{}
			// 序号dfloat
			j := 5
			svrmsg.NbSlu_5200.CmdIdx = int32(dd[j])
			j++
			// 经纬度
			x, _ := strconv.ParseFloat(fmt.Sprintf("%d.%02d", dd[j], int(dd[j+1])), 10)
			svrmsg.NbSlu_5200.Longitude = x
			j += 2
			x, _ = strconv.ParseFloat(fmt.Sprintf("%d.%02d", dd[j], int(dd[j+1])), 10)
			svrmsg.NbSlu_5200.Latitude = x
			j += 2
			// 投停运
			m := fmt.Sprintf("%02x", dd[j])
			if gopsu.String2Int32(m[:1], 10) == 5 {
				svrmsg.NbSlu_5200.SluitemEnableAlarm = 1
			} else if gopsu.String2Int32(m[:1], 10) == 10 {
				svrmsg.NbSlu_5200.SluitemEnableAlarm = 0
			}
			if gopsu.String2Int32(m[1:2], 10) == 5 {
				svrmsg.NbSlu_5200.SluitemStatus = 1
			} else if gopsu.String2Int32(m[1:2], 10) == 10 {
				svrmsg.NbSlu_5200.SluitemStatus = 0
			}
			j++
			// 默认上电开关灯
			m = fmt.Sprintf("%08b", dd[j])
			for k := range m[4:8] {
				if gopsu.String2Int32(m[7-k:8-k], 2) == 0 {
					svrmsg.NbSlu_5200.SluitemPowerTurnon = append(svrmsg.NbSlu_5200.SluitemPowerTurnon, 1)
				} else {
					svrmsg.NbSlu_5200.SluitemPowerTurnon = append(svrmsg.NbSlu_5200.SluitemPowerTurnon, 0)
				}
			}
			j++
			// 额定功率
			for i := 0; i < 4; i++ {
				svrmsg.NbSlu_5200.RatedPower = append(svrmsg.NbSlu_5200.RatedPower, int32(dd[j])+int32(dd[j+1])*256)
				j += 2
			}
			// 主报参数
			m = fmt.Sprintf("%08b", dd[j])
			repflg := gopsu.String2Int32(m[:1], 2)
			svrmsg.NbSlu_5200.UplinkReply = repflg
			svrmsg.NbSlu_5200.UplinkTimer = gopsu.String2Int32(m[1:], 2) * 5
			if svrmsg.NbSlu_5200.UplinkTimer == 0 {
				svrmsg.NbSlu_5200.UplinkTimer = 30
			}
			j++
			// 实际使用回路数
			svrmsg.NbSlu_5200.UseLoop = int32(dd[j]) + 1
			j++
			// 反向调光
			m = fmt.Sprintf("%08b", dd[j])
			for i := 7; i >= 4; i-- {
				svrmsg.SluitemConfig.SluitemPara.SluitemReverseDimming = append(svrmsg.SluitemConfig.SluitemPara.SluitemReverseDimming, int32(m[i]-48))
			}
			j++
			j += 3
		case 0xd4: // 即时控制应答
			svrmsg.DataType = 6
			f.DataCmd = "wlst.vslu.5400"
			svrmsg.NbSlu_5400 = &msgnb.NBSlu_5400{}
			// 序号
			j := 5
			svrmsg.NbSlu_5400.CmdIdx = int32(dd[j])
			j++
			svrmsg.NbSlu_5400.Status = int32(dd[j])
		case 0xd5: // 复位应答
			svrmsg.DataType = 7
			f.DataCmd = "wlst.vslu.5500"
			svrmsg.NbSlu_5500 = &msgnb.NBSlu_5500{}
			// 序号
			j := 5
			svrmsg.NbSlu_5500.CmdIdx = int32(dd[j])
			j++
			m := fmt.Sprintf("%08b", dd[j])
			m1 := fmt.Sprintf("%08b", dd[j+1])
			if m[2:3] == "1" {
				if m1[2:3] == "1" {
					svrmsg.NbSlu_5500.InitializeElec = 1
				} else {
					svrmsg.NbSlu_5500.InitializeElec = 0
				}
			} else {
				svrmsg.NbSlu_5500.InitializeElec = 2
			}
			if m[7:8] == "1" {
				if m1[7:8] == "1" {
					svrmsg.NbSlu_5500.Mcu = 1
				} else {
					svrmsg.NbSlu_5500.Mcu = 0
				}
			} else {
				svrmsg.NbSlu_5500.Mcu = 2
			}
		case 0xd6: // 设置本地控制方案应答
			svrmsg.DataType = 8
			f.DataCmd = "wlst.vslu.5600"
			svrmsg.NbSlu_5600 = &msgnb.NBSlu_5600{}
			// 序号
			j := 5
			svrmsg.NbSlu_5600.CmdIdx = int32(dd[j])
			j++
			svrmsg.NbSlu_5600.Status = int32(dd[j])
		case 0xd7: // 读取本地控制方案
			svrmsg.DataType = 8
			f.DataCmd = "wlst.vslu.5700"
			svrmsg.NbSlu_5600 = &msgnb.NBSlu_5600{}
			// 序号
			j := 5
			svrmsg.NbSlu_5600.CmdIdx = int32(dd[j])
			j++
			// 本地方案数量
			s := fmt.Sprintf("%08b", dd[j])
			if s[0] == 49 {
				svrmsg.NbSlu_5600.DataContinue = 1
			}
			svrmsg.NbSlu_5600.SluitemRuntimeCount = int32(gopsu.String2Int32(s[2:], 2))
			j++
			// 本地方案参数
			for i := int32(0); i < svrmsg.NbSlu_5600.SluitemRuntimeCount; i++ {
				sr := &msgnb.NBSlu_5600_SluitemRuntime{}
				// 操作类型
				m := fmt.Sprintf("%08b", dd[j])
				sr.OutputType = gopsu.String2Int32(m[4:], 2)
				sr.OperateType = gopsu.String2Int32(m[:4], 2)
				j++
				// 周使能
				m = fmt.Sprintf("%08b", dd[j])
				for k := 0; k < 7; k++ {
					sr.DateEnable = append(sr.DateEnable, gopsu.String2Int32(m[7-k:8-k], 2))
				}
				j++
				// 控制时刻
				switch sr.OperateType {
				case 1:
					sr.OperateTime = int32(dd[j])*60 + int32(dd[j+1])
				case 2:
					m = fmt.Sprintf("%016b", int32(dd[j])*60+int32(dd[j+1]))
					y := gopsu.String2Int32(m[1:], 2)
					if m[0] == 49 {
						sr.OperateOffset = 0 - int32(y)
					} else {
						sr.OperateOffset = int32(y)
					}
				}
				j += 2
				// 控制操作
				m = fmt.Sprintf("%08b", dd[j])
				n := fmt.Sprintf("%08b", dd[j+1])
				switch sr.OutputType {
				case 0:
					y, _ := strconv.ParseInt(m[4:], 2, 0)
					x, _ := strconv.ParseInt(m[:4], 2, 0)
					sr.RelayOperate = append(sr.RelayOperate, int32(y), int32(x))
					y, _ = strconv.ParseInt(n[4:], 2, 0)
					x, _ = strconv.ParseInt(n[:4], 2, 0)
					sr.RelayOperate = append(sr.RelayOperate, int32(y), int32(x))
				case 1:
					sr.PwmLoop = append(sr.PwmLoop, gopsu.String2Int32(m[7:8], 10), gopsu.String2Int32(m[6:7], 10), gopsu.String2Int32(m[5:6], 10), gopsu.String2Int32(m[4:5], 10))
					x, _ := strconv.ParseInt(m[:4], 2, 0)
					y, _ := strconv.ParseInt(n[:4], 2, 0)
					sr.PwmPower = int32(x)*10 + int32(y)
					z, _ := strconv.ParseInt(n[4:], 2, 0)
					sr.PwmBaudrate = int32(z) * 100
				}
				j += 2

				svrmsg.NbSlu_5600.SluitemRuntime = append(svrmsg.NbSlu_5600.SluitemRuntime, sr)
			}
		case 0xb1: // 设置网络参数应答
			svrmsg.DataType = 11
			f.DataCmd = "wlst.vslu.3100"
			svrmsg.NbSlu_3100 = &msgnb.NBSlu_3100{}
			// 序号
			j := 5
			svrmsg.NbSlu_3100.CmdIdx = int32(dd[j])
			j++
			svrmsg.NbSlu_3100.Status = int32(dd[j])
		case 0xb3: // 查询网络参数
			svrmsg.DataType = 11
			f.DataCmd = "wlst.vslu.3300"
			svrmsg.NbSlu_3100 = &msgnb.NBSlu_3100{}
			// 序号
			j := 5
			svrmsg.NbSlu_3100.CmdIdx = int32(dd[j])
			j++
			svrmsg.NbSlu_3100.Apn = string(dd[j : j+32])
			j += 32
			svrmsg.NbSlu_3100.UserName = string(dd[j : j+32])
			j += 32
			svrmsg.NbSlu_3100.Password = string(dd[j : j+32])
			j += 32
			svrmsg.NbSlu_3100.Operater = int32(dd[j])
			j++
			svrmsg.NbSlu_3100.IpAddress = append(svrmsg.NbSlu_3100.IpAddress, int32(dd[j]), int32(dd[j+1]), int32(dd[j+2]), int32(dd[j+3]))
			j += 4
			svrmsg.NbSlu_3100.Teleport = int32(dd[j]) + int32(dd[j+1])*256
			j += 2
			svrmsg.NbSlu_3100.Localport = int32(dd[j]) + int32(dd[j+1])*256
			j += 2
			svrmsg.NbSlu_3100.VlinkTime = int32(dd[j]) + int32(dd[j+1])*256
			j += 2
			svrmsg.NbSlu_3100.GroupAccessInterval = int32(dd[j])
			j++
			svrmsg.NbSlu_3100.GroupDeviceCount = int32(dd[j])
			j++
			svrmsg.NbSlu_3100.MaxDeviceCount = int32(dd[j]) + int32(dd[j+1])*256
			j += 2
		default:
			f.Ex = "Unhandled nbslu data"
			lstf = append(lstf, f)
			return lstf
		}
	default:
		f.Ex = "Unhandled NB data"
		lstf = append(lstf, f)
		return lstf
	}

	if len(f.DataCmd) > 0 {
		svrmsg.DataCmd = f.DataCmd
		f.DataMsg = CodePb2NB(svrmsg)
		lstf = append(lstf, f)
	}

	return lstf
}
