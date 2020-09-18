package shv1

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/xyzj/gopsu"
	wlstsh "gitlab.local/proto/msgshv1"
)

// ParseCtl 解析下行
func (dp *DataProcessor) ParseCtl(b []byte) (lstf []*Fwd) {
	defer func() {
		if ex := recover(); ex != nil {
			f := &Fwd{
				Ex: fmt.Sprintf("Parse Ctl error: %+v", errors.WithStack(ex.(error))),
			}
			lstf = append(lstf, f)
		}
	}()
	var pb2data = &wlstsh.MsgSHv1{}
	err := pb2data.Unmarshal(b)
	if err != nil {
		panic(err.Error())
	}

	var d bytes.Buffer
	switch pb2data.DataID.Afn {
	case 0x00: // 确认/否认
		for _, v := range pb2data.DataID.UintID {
			switch v.Pn {
			case 0:
				switch v.Fn {
				case 1: // 全部确认
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
				case 2: // 全部否认
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
				}
			}
		}
	case 0x01: // 复位
		for _, v := range pb2data.DataID.UintID {
			switch v.Pn {
			case 0:
				switch v.Fn {
				case 1: // 终端复位
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
				case 2: // GPRS重连指令
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
				}
			}
		}
	case 0x02: // 链路接口检测
	case 0x04: // 设置参数
		for _, v := range pb2data.DataID.UintID {
			switch v.Pn {
			case 0:
				switch v.Fn {
				case 3: // 终端事件记录配置设置
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					rs := []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
					for _, v := range pb2data.Afn04P0F3.Report {
						rs[v-1] = "1"
					}
					s1 := gopsu.ReverseString(strings.Join(rs, ""))
					d.Write([]byte{gopsu.String2Int8(s1[56:64], 2), gopsu.String2Int8(s1[48:56], 2), gopsu.String2Int8(s1[40:48], 2), gopsu.String2Int8(s1[32:40], 2), gopsu.String2Int8(s1[16:32], 2), gopsu.String2Int8(s1[8:16], 2), gopsu.String2Int8(s1[0:8], 2)})

					rs = []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
					for _, v := range pb2data.Afn04P0F3.Import {
						rs[v-1] = "1"
					}
					s1 = gopsu.ReverseString(strings.Join(rs, ""))
					d.Write([]byte{gopsu.String2Int8(s1[56:64], 2), gopsu.String2Int8(s1[48:56], 2), gopsu.String2Int8(s1[40:48], 2), gopsu.String2Int8(s1[32:40], 2), gopsu.String2Int8(s1[16:32], 2), gopsu.String2Int8(s1[8:16], 2), gopsu.String2Int8(s1[0:8], 2)})

					rs = []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
					for _, v := range pb2data.Afn04P0F3.Normal {
						rs[v-1] = "1"
					}
					s1 = gopsu.ReverseString(strings.Join(rs, ""))
					d.Write([]byte{gopsu.String2Int8(s1[56:64], 2), gopsu.String2Int8(s1[48:56], 2), gopsu.String2Int8(s1[40:48], 2), gopsu.String2Int8(s1[32:40], 2), gopsu.String2Int8(s1[16:32], 2), gopsu.String2Int8(s1[8:16], 2), gopsu.String2Int8(s1[0:8], 2)})

				case 4: // 设备基本信息
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F4.CboxNumber), "%012.0f"))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F4.TmlPhyid), "%016.0f"))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F4.Longitude*100000), "%010.2f"))
					d.Write(gopsu.Float642BcdBytes(float64(pb2data.Afn04P0F4.Latitude*100000), "%010.2f"))
					d.WriteByte(byte(pb2data.Afn04P0F4.UseSlu))
					d.Write([]byte{byte(pb2data.Afn04P0F4.SluFreq % 256), byte(pb2data.Afn04P0F4.SluFreq / 256)})

				case 9: // 控制器开关灯时间参数
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.Write([]byte{gopsu.String2Int8(pb2data.Afn04P0F9.DtStart[0:2], 10), gopsu.String2Int8(pb2data.Afn04P0F9.DtStart[2:4], 10)})
					d.Write([]byte{byte(pb2data.Afn04P0F9.Days % 256), byte(pb2data.Afn04P0F9.Days / 256)})
					for _, v := range pb2data.Afn04P0F9.TimeSlot {
						d.Write(gopsu.Float642BcdBytes(float64(v.TimeOn%60), "%02.0f"))
						d.Write(gopsu.Float642BcdBytes(float64(v.TimeOn/60), "%02.0f"))
						d.Write(gopsu.Float642BcdBytes(float64(v.TimeOff%60), "%02.0f"))
						d.Write(gopsu.Float642BcdBytes(float64(v.TimeOff/60), "%02.0f"))
					}

				case 12: // 控制回路参数
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					rs := []string{"0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"}
					for _, v := range pb2data.Afn04P0F12.LoopNo {
						rs[v-1] = "1"
					}
					s1 := gopsu.ReverseString(strings.Join(rs, ""))
					d.Write([]byte{gopsu.String2Int8(s1[8:16], 2), gopsu.String2Int8(s1[0:8], 2)})
					re := []string{"0", "0", "0", "0", "0", "0", "0", "0"}
					for _, v := range pb2data.Afn04P0F12.EngNo {
						re[v-1] = "1"
					}
					s2 := gopsu.ReverseString(strings.Join(re, ""))
					d.WriteByte(byte(gopsu.String2Int8(s2, 2)))
					d.WriteByte(byte(pb2data.Afn04P0F12.EngLevel))

				case 25: // 遥信量分类参数
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(len(pb2data.Afn04P0F25.LoopInfo)))
					d.WriteByte(byte(pb2data.Afn04P0F25.LoopStart))
					for _, v := range pb2data.Afn04P0F25.LoopInfo {
						d.WriteByte(byte(v.Type))
						d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%d%07d", v.InOut, v.Index), 2))
						d.WriteByte(byte(v.Phase))
					}
				}
			}
		}
	case 0x05: // 控制命令
		for _, v := range pb2data.DataID.UintID {
			switch v.Pn {
			case 0:
				switch v.Fn {
				case 1: // 控制器遥控操作
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(pb2data.Afn05P0F1.CtlType))
					d.WriteByte(byte(pb2data.Afn05P0F1.EngLevel))

				case 31: // 对时命令
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					y, M, D, h, m, s, w := gopsu.SplitDateTime(pb2data.Afn05P0F31.Time)
					if w == 0 {
						w = 7
					}
					d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04d%04d", s/10, s%10), 2))
					d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04d%04d", m/10, m%10), 2))
					d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04d%04d", h/10, h%10), 2))
					d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04d%04d", D/10, D%10), 2))
					d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%03d%d%04d", w, M/10, M%10), 2))
					d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04d%04d", y/10, y%10), 2))

				}
			}
		}
	case 0x09: // 请求终端配置及信息
		for _, v := range pb2data.DataID.UintID {
			switch v.Pn {
			case 0:
				switch v.Fn {
				case 1: // 终端信息
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
				}
			}
		}
	case 0x0c: // 请求实时数据
		for _, v := range pb2data.DataID.UintID {
			switch v.Pn {
			case 0:
				switch v.Fn {
				case 11: // 模拟量批量查询
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(pb2data.Afn0CP0F11.LoopNum))
					d.WriteByte(byte(pb2data.Afn0CP0F11.LoopStart))

				case 12: // 状态量批量查询
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(pb2data.Afn0CP0F12.LoopNum))
					d.WriteByte(byte(pb2data.Afn0CP0F12.LoopStart))
				}
			}
		}
	case 0x0e: // 请求事件数据
		for _, v := range pb2data.DataID.UintID {
			switch v.Pn {
			case 0:
				switch v.Fn {
				case 1: // 请求重要事件
					d.Write(setPnFn(v.Pn))
					d.Write(setPnFn(v.Fn))
					d.WriteByte(byte(pb2data.Afn0EP0F1.Pm))
					d.WriteByte(byte(pb2data.Afn0EP0F1.Pn))

				}
			}
		}

	default:
	}
	if d.Len() > 0 {
		ff := &Fwd{
			DataCmd:  fmt.Sprintf("shv1.rtu.%02x", pb2data.DataID.Afn),
			DataType: DataTypeBytes,
			DataDst:  fmt.Sprintf("shv1-rtu-%016d", pb2data.DataID.Addr),
			DstType:  SockTml,
			DataMsg:  dp.BuildCommand(d.Bytes(), pb2data.DataID.Addr, 0, 1, 1, pb2data.DataID.Seq),
			Tra:      TraDirect,
			Job:      JobSend,
		}
		lstf = append(lstf, ff)
	}
	return lstf
}
