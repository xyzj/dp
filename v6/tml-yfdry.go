package v6

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/xyzj/gopsu"
	msgctl "github.com/xyzj/proto/msgjk"
)

// ProcessYfDry 处理基于ip的设备数据
func (dp *DataProcessor) ProcessYfDry(d []byte) (r *Rtb) {
	r = &Rtb{}
	defer func() {
		if ex := recover(); ex != nil {
			r.Src = gopsu.Bytes2String(d, "-")
			r.Ex = fmt.Sprintf("%+v", errors.WithStack(ex.(error)))
		}
	}()

	if len(d) < 6 {
		return r
	}
	// 判断是否心跳
	if string(d[:6]) == "      " {
		// f := &Fwd{
		// 	Addr:     1,
		// 	DataCmd:  "wlst.rtu.2000",
		// 	DataPT:   3000,
		// 	DataType: DataTypeBytes,
		// 	DataDst:  fmt.Sprintf("wlst-rtu-%d", 1),
		// 	DstType:  1,
		// 	Tra:      TraDirect,
		// 	Job:      JobSend,
		// 	Src:      gopsu.Bytes2String(d, "-"),
		// 	DataMsg:  Send2000,
		// }
		// r.Do = append(r.Do, f)
		return r
	}
	// 判断是否门锁设备
	// if d[0] == 0x7e {
	// 	r.Do = append(r.Do, dp.dataHJLock(d, 1, 0)...)
	// 	return r
	// }
	l := int(d[2]) + 5
	if len(d) < l {
		r.Unfinish = d
		return r
	}
	// 不是门锁，默认远帆除湿
	r.Do = append(r.Do, dp.dataYfDry(d[:l], 1, 0)...)
	return r
}

// 远帆除湿
func (dp *DataProcessor) dataYfDry(d []byte, tra byte, parentID int64) (lstf []*Fwd) {
	var f = &Fwd{
		DataType: DataTypeBase64,
		DataDst:  "2",
		DstType:  SockData,
		Tra:      TraDirect,
		Job:      JobSend,
		Src:      gopsu.Bytes2String(d, "-"),
	}

	if !gopsu.CheckCrc16VB(d) {
		f.Ex = fmt.Sprintf("locker data validation fails")
		lstf = append(lstf, f)
		return lstf
	}
	var cid int32
	cmd := d[1]
	if parentID == 0 {
		f.Addr = int64(d[0])
		cid = 1
		f.Tra = TraDirect
	} else {
		f.Addr = parentID
		cid = int32(d[0])
		f.Tra = Tra485
	}
	svrmsg := initMsgCtl(fmt.Sprintf("yf.dry.%02x00", cmd), f.Addr, dp.RemoteIP, 1, tra, cid, &dp.LocalPort)
	svrmsg.Args.Sim = dp.SIM
	f.DataCmd = svrmsg.Head.Cmd
	switch cmd {
	case 0x03: // 读取数据
		svrmsg.YfDry_0300 = &msgctl.YfDry_0300{}
		svrmsg.YfDry_0300.Addr = int32(d[0])
		svrmsg.YfDry_0300.CtlStatus = int32(d[3])*256 + int32(d[4])
		svrmsg.YfDry_0300.DewPoint = int32(d[5])*256 + int32(d[6])
		svrmsg.YfDry_0300.Humidity = int32(d[7])*256 + int32(d[8])
		svrmsg.YfDry_0300.Temperature = int32(d[9])*256 + int32(d[10])
		svrmsg.YfDry_0300.HumidityUplimit = int32(d[11])*256 + int32(d[12])
		svrmsg.YfDry_0300.HumidityLowlimit = int32(d[13])*256 + int32(d[14])
		svrmsg.YfDry_0300.TemperatureUplimit = int32(d[15])*256 + int32(d[16])
		svrmsg.YfDry_0300.TemperatureLowlimit = int32(d[17])*256 + int32(d[18])
	case 0x10: // 设置数据
		switch d[2] {
		case 2: // 控制
			svrmsg.YfDry_1001 = &msgctl.YfDry_1001{}
			svrmsg.YfDry_1001.Addr = int32(d[0])
		case 8: // 设置参数
			svrmsg.YfDry_1005 = &msgctl.YfDry_1005{}
			svrmsg.YfDry_1005.Addr = int32(d[0])
		}
	}

	if len(f.DataCmd) > 0 {
		b, _ := svrmsg.Marshal()
		f.DataMsg = b
		lstf = append(lstf, f)
	}
	return lstf
}
