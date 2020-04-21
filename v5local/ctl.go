package dpv5

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	pb2 "github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/xyzj/gopsu"
	msgctl "gitlab.local/proto/msgjk"
	msgnb "gitlab.local/proto/msgnb"
)

// ClassifyCtrlDataGrpc 解析grpc数据
func ClassifyCtrlDataGrpc(msg *msgctl.MsgWithCtrl, port *int) (r *Rtb) {
	r = &Rtb{}
	r.Do = append(r.Do, dataWlst(msg, port)...)
	return r
}

// ClassifyCtlData 中间层等数据解析
func ClassifyCtlData(d []byte, port *int) (r *Rtb) {
	r = &Rtb{}
	defer func() {
		if ex := recover(); ex != nil {
			r.Src = base64.StdEncoding.EncodeToString(d)
			r.Ex = fmt.Sprintf("%+v", errors.WithStack(ex.(error)))
		}
	}()
LOOP:
	p1 := bytes.IndexAny(d, ctlHead)
	p2 := bytes.IndexAny(d[p1+1:], ctlHead)
	if p1 > -1 && p2 > -1 {
		b, err := base64.StdEncoding.DecodeString(string(d[p1+1 : p1+p2+1]))
		if err == nil {
			r.Do = append(r.Do, dataCtl(b, port)...)
		} else {
			if strings.Contains(string(d[p1+1:p1+p2+1]), "{") {
				r.Do = append(r.Do, dataCtl(d[p1+1:p1+p2+1], port)...)
			}
		}
		d = d[p1+p2+2:]
		if len(d) == 0 {
			return r
		}
		goto LOOP
	} else {
		r.Unfinish = d
	}
	return r
}

// ClassifyCtlDataNoB64 ClassifyCtlDataNoB64
func ClassifyCtlDataNoB64(d []byte, port *int) (r *Rtb) {
	r = &Rtb{}
	r.Do = append(r.Do, dataCtl(d, port)...)
	return r
}

func dataCtlJSON(data []byte) (lstf []*Fwd) {
	defer func() {
		if ex := recover(); ex != nil {
			f := &Fwd{
				Ex:  fmt.Sprintf("%+v", errors.WithStack(ex.(error))),
				Src: string(data),
			}
			lstf = append(lstf, f)
		}
	}()
	data = bytes.ToLower(data)
	getprotocol := true
	cmd := gjson.GetBytes(data, "head.cmd").String()
	tra := byte(gjson.GetBytes(data, "head.tra").Int())
	cid := byte(gjson.GetBytes(data, "args.cid").Int())
	var br, rc byte
	// if a := gjson.GetBytes(data, "args.br"); a.Exists() {
	// 	br = byte(a.Int())
	// } else {
	// 	br = 5
	// }
	//
	// if a := gjson.GetBytes(data, "args.rc"); a.Exists() {
	// 	rc = byte(a.Int())
	// } else {
	// 	rc = 0
	// }
	if gjson.GetBytes(data, "head.src").Int() > 1 {
		switch gjson.GetBytes(data, "head.mod").Int() {
		case 1:
		case 2: // 数传
			scmd := strings.Split(gjson.GetBytes(data, "head.cmd").String(), ".")
			var d bytes.Buffer
			var xaddrs []int64
			if xa := gjson.GetBytes(data, "args.addr"); xa.Exists() && len(xa.Array()) > 0 {
				xaddrs = make([]int64, 0, len(xa.Array()))
				for _, v := range xa.Array() {
					xaddrs = append(xaddrs, v.Int())
				}
			} else if xa := gjson.GetBytes(data, "args.saddr"); xa.Exists() && len(xa.Array()) > 0 {
				xaddrs = make([]int64, 0, len(xa.Array()))
				for _, v := range xa.Array() {
					if len(v.String()) > 0 {
						if strings.Contains(v.String(), "-") {
							s := strings.Split(v.String(), "-")
							for i := gopsu.String2Int64(s[0], 10); i <= gopsu.String2Int64(s[1], 10); i++ {
								xaddrs = append(xaddrs, i)
							}
						} else {
							xaddrs = append(xaddrs, gopsu.String2Int64(v.String(), 10))
						}
					}
				}
			}
			ld := gjson.GetBytes(data, "data")
			switch scmd[0] {
			case "wlst":
				switch scmd[1] {
				case "rtu":
					switch scmd[2] {
					case "4000":
						d.WriteByte(byte(ld.Get("mark").Int()))
						d.WriteByte(2)
						d.WriteByte(byte(ld.Get("kl").Int()))
						d.WriteByte(byte(ld.Get("ar").Int()))
						d.WriteByte(5)
						d.WriteByte(byte(ld.Get("l2").Int()))
						d.WriteByte(byte(ld.Get("l1").Int()))
						d.WriteByte(byte(ld.Get("l3").Int()))
						d.WriteByte(byte(ld.Get("ad").Int()))
						d.WriteByte(byte(ld.Get("l4").Int()))
						d.WriteByte(byte(ld.Get("l5").Int()))
						d.WriteByte(byte(ld.Get("l6").Int()))
						if a := ld.Get("l7"); a.Exists() {
							d.WriteByte(byte(a.Int()))
						}
						if a := ld.Get("l8"); a.Exists() {
							d.WriteByte(byte(a.Int()))
						}
					case "4101":
						d.WriteByte(0x1)
						d.WriteByte(byte(ld.Get("ln").Int() + 1))
						d.WriteByte(byte(ld.Get("vr").Int() / 5))
						d.Write(Single2Tribytes(float64(ld.Get("vr").Int()) / 0x3ff0))
						// d.WriteByte(0)
						// d.WriteByte(0)
						// d.WriteByte(0)
						l := int(ld.Get("ln").Int() + 1)
						for i := 1; i < l; i++ {
							d.WriteByte(byte(ld.Get(fmt.Sprintf("l%d", i)).Int() / 5))
							d.Write(Single2Tribytes(float64(ld.Get(fmt.Sprintf("l%d", i)).Int()) / 0x3ff0))
							// d.WriteByte(0)
							// d.WriteByte(0)
							// d.WriteByte(0)
						}
					case "4102":
						d.WriteByte(0x2)
					case "4104":
						d.WriteByte(0x4)
						d.WriteByte(byte(ld.Get("ln").Int()))
						l := int(ld.Get("ln").Int() + 1)
						for i := 1; i < l; i++ {
							d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04b%04b", ld.Get(fmt.Sprintf("l%dv", i)).Int()-1, ld.Get(fmt.Sprintf("l%dt", i)).Int()*0xf), 2))
						}
					case "4108":
						d.WriteByte(0x8)
					case "4110":
						d.WriteByte(0x10)
						d.WriteByte(byte(ld.Get("ln").Int()))
					case "4201":
						d.WriteByte(0x1)
						d.WriteByte(0)
						l := int(ld.Get("ln").Int() + 1)
						for i := 1; i < l; i++ {
							d.WriteByte(byte(ld.Get(fmt.Sprintf("l%d", i)).Int() - 1))
						}
					case "4202":
						d.WriteByte(0x2)
					case "4204":
						d.WriteByte(0x4)
						l := int(ld.Get("ln").Int() + 1)
						for i := 1; i < l; i++ {
							d.WriteByte(byte(ld.Get(fmt.Sprintf("l%d", i)).Int() - 1))
						}
					case "4208":
						d.WriteByte(0x8)
					case "4210":
						d.WriteByte(0x10)
						l := int(ld.Get("ln").Int() + 1)
						for i := 1; i < l; i++ {
							d.WriteByte(byte(ld.Get(fmt.Sprintf("l%d", i)).Int() - 1))
						}
					case "4400", "4401":
						d.WriteByte(0x01)
						d.WriteByte(byte(int(ld.Get("vql").Float()/ld.Get("vr").Float()*0x3ff0) & 0xff))
						d.WriteByte(byte(int(ld.Get("vql").Float()/ld.Get("vr").Float()*0x3ff0/256) & 0xff))
						d.WriteByte(byte(int(ld.Get("vqu").Float()/ld.Get("vr").Float()*0x3ff0) & 0xff))
						d.WriteByte(byte(int(ld.Get("vqu").Float()/ld.Get("vr").Float()*0x3ff0/256) & 0xff))
						l := int(ld.Get("ln").Int() + 1)
						for i := 1; i < l; i++ {
							if ld.Get(fmt.Sprintf("l%d", i)).Int() > 0 {
								d.WriteByte(byte(int(ld.Get(fmt.Sprintf("l%dql", i)).Float()/ld.Get(fmt.Sprintf("l%d", i)).Float()*0x3ff0) & 0xff))
								d.WriteByte(byte(int(ld.Get(fmt.Sprintf("l%dql", i)).Float()/ld.Get(fmt.Sprintf("l%d", i)).Float()*0x3ff0/256) & 0xff))
								d.WriteByte(byte(int(ld.Get(fmt.Sprintf("l%dqu", i)).Float()/ld.Get(fmt.Sprintf("l%d", i)).Float()*0x3ff0) & 0xff))
								d.WriteByte(byte(int(ld.Get(fmt.Sprintf("l%dqu", i)).Float()/ld.Get(fmt.Sprintf("l%d", i)).Float()*0x3ff0/256) & 0xff))
							} else {
								d.WriteByte(0)
								d.WriteByte(0)
								d.WriteByte(0)
								d.WriteByte(0)
							}
						}
					case "6100":
						for i := 0; i < 36; i += 4 {
							d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%02b%02b%02b%02b",
								ld.Get(fmt.Sprintf("s%dv", i+4)).Int(),
								ld.Get(fmt.Sprintf("s%dv", i+3)).Int(),
								ld.Get(fmt.Sprintf("s%dv", i+2)).Int(),
								ld.Get(fmt.Sprintf("s%dv", i+1)).Int()), 2))
						}
					case "2200", "2210":
						d.WriteByte(0x10)
						d.WriteByte(byte(ld.Get("k").Int() - 1))
						if ld.Get("o").Int() == 1 {
							d.WriteByte(0xff)
						} else {
							d.WriteByte(0)
						}
					case "4b00":
						cmd = ""
						for i := 1; i < 7; i++ {
							d22 := make([]byte, 0, 3)
							switch ld.Get(fmt.Sprintf("k%d", i)).Int() {
							case 0:
								d22 = append(d22, 0x10, byte(i-1), 0)
							case 1:
								d22 = append(d22, 0x10, byte(i-1), 0xff)
							}
							if len(d22) > 0 {
								for _, v := range xaddrs {
									f := &Fwd{
										DataMsg: DoCommand(byte(gjson.GetBytes(data, "head.ver").Int()), byte(gjson.GetBytes(data, "head.tver").Int()), tra, v, int32(cid), "wlst.rtu.2200", d22, br, rc),
										// DataMsg:  gopsu.Bytes2String(DoCommand(byte(gjson.GetBytes(data, "head.ver").Int()), byte(gjson.GetBytes(data, "head.tver").Int()), tra, v, int32(cid), "wlst.rtu.2200", d22, br, rc), "-"),
										DataDst:  fmt.Sprintf("%s-%d", strings.Join(scmd[:2], "-"), v),
										DataCmd:  "wlst.rtu.2200",
										DataSP:   byte(ld.Get("head.ret").Int()),
										DataPT:   3000,
										DataType: DataTypeBytes,
										Job:      JobSend,
										Tra:      tra,
										Addr:     v,
										// Src:      fmt.Sprintf("%v", pb2data),
										DstType: 1,
									}
									lstf = append(lstf, f)
								}
							}
						}
					case "1200":
						// a := strings.Split(ld.Get("date").String(), " ")
						// y := strings.Split(a[0], "-")
						// h := strings.Split(a[1], ":")
						// d.WriteByte(byte(gopsu.String2Int32(y[0], 10) - 2000))
						// 为兼容老设备，不发秒字节
						// d.Write([]byte{gopsu.String2Int8(y[1], 10), gopsu.String2Int8(y[2], 10), gopsu.String2Int8(h[0], 10), gopsu.String2Int8(h[1], 10), gopsu.String2Int8(a[2], 10)})
						d.Write(GetServerTimeMsg(0, 1, true, true))
					case "3100":
						for i := 0; i < 7; i++ {
							t := strings.Split(ld.Get(fmt.Sprintf("w%dk1", i)).String(), "-")
							h := gopsu.String2Int8(t[0][:2], 10)
							m := gopsu.String2Int8(t[0][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							h = gopsu.String2Int8(t[1][:2], 10)
							m = gopsu.String2Int8(t[1][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							t = strings.Split(ld.Get(fmt.Sprintf("w%dk2", i)).String(), "-")
							h = gopsu.String2Int8(t[0][:2], 10)
							m = gopsu.String2Int8(t[0][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							h = gopsu.String2Int8(t[1][:2], 10)
							m = gopsu.String2Int8(t[1][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							t = strings.Split(ld.Get(fmt.Sprintf("w%dk3", i)).String(), "-")
							h = gopsu.String2Int8(t[0][:2], 10)
							m = gopsu.String2Int8(t[0][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							h = gopsu.String2Int8(t[1][:2], 10)
							m = gopsu.String2Int8(t[1][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							t = strings.Split(ld.Get(fmt.Sprintf("w%dcp", i)).String(), "-")
							h = gopsu.String2Int8(t[0][:2], 10)
							m = gopsu.String2Int8(t[0][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							t = strings.Split(ld.Get(fmt.Sprintf("w%dsp", i)).String(), "-")
							h = gopsu.String2Int8(t[0][:2], 10)
							m = gopsu.String2Int8(t[0][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
						}
						d.WriteByte(0)
					case "5800":
						for i := 0; i < 7; i++ {
							t := strings.Split(ld.Get(fmt.Sprintf("w%dk4", i)).String(), "-")
							h := gopsu.String2Int8(t[0][:2], 10)
							m := gopsu.String2Int8(t[0][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							h = gopsu.String2Int8(t[1][:2], 10)
							m = gopsu.String2Int8(t[1][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							t = strings.Split(ld.Get(fmt.Sprintf("w%dk5", i)).String(), "-")
							h = gopsu.String2Int8(t[0][:2], 10)
							m = gopsu.String2Int8(t[0][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							h = gopsu.String2Int8(t[1][:2], 10)
							m = gopsu.String2Int8(t[1][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							t = strings.Split(ld.Get(fmt.Sprintf("w%dk6", i)).String(), "-")
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
					case "6800":
						for i := 0; i < 7; i++ {
							t := strings.Split(ld.Get(fmt.Sprintf("w%dk7", i)).String(), "-")
							h := gopsu.String2Int8(t[0][:2], 10)
							m := gopsu.String2Int8(t[0][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							h = gopsu.String2Int8(t[1][:2], 10)
							m = gopsu.String2Int8(t[1][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							t = strings.Split(ld.Get(fmt.Sprintf("w%dk8", i)).String(), "-")
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
					case "4600", "6500":
						l := 7
						if a := ld.Get("d1k7"); a.Exists() {
							if a.Int() != -1 {
								l = 9
							}
						}
						for i := 1; i < 5; i++ {
							t := strings.Split(ld.Get(fmt.Sprintf("d%d", i)).String(), "-")
							h := gopsu.String2Int8(t[0][:2], 10)
							m := gopsu.String2Int8(t[0][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							h = gopsu.String2Int8(t[1][:2], 10)
							m = gopsu.String2Int8(t[1][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							for j := 1; j < l; j++ {
								t = strings.Split(ld.Get(fmt.Sprintf("d%dk%d", i, j)).String(), "-")
								h = gopsu.String2Int8(t[0][:2], 10)
								m = gopsu.String2Int8(t[0][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
								h = gopsu.String2Int8(t[1][:2], 10)
								m = gopsu.String2Int8(t[1][2:], 10)
								d.WriteByte(gopsu.Int82Bcd(h))
								d.WriteByte(gopsu.Int82Bcd(m))
							}
							t = strings.Split(ld.Get(fmt.Sprintf("d%dcp", i)).String(), "-")
							h = gopsu.String2Int8(t[0][:2], 10)
							m = gopsu.String2Int8(t[0][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
							t = strings.Split(ld.Get(fmt.Sprintf("d%dsp", i)).String(), "-")
							h = gopsu.String2Int8(t[0][:2], 10)
							m = gopsu.String2Int8(t[0][2:], 10)
							d.WriteByte(gopsu.Int82Bcd(h))
							d.WriteByte(gopsu.Int82Bcd(m))
						}
						d.WriteByte(0)
					case "2000", "5c00", "3200", "5900", "6900", "5a00", "2500", "4700", "1300", "2900", "5d00", "7700", "2b00", "2800", "3900", "6600": // 终端选测/招测版本/招测参数/招测节假日/停运/解除停运
					default:
						getprotocol = false
					}
				case "ldu":
					br = 2
					rc = 5
					switch scmd[2] {
					case "4900":
						d.WriteByte(byte(ld.Get("ln").Int()))
						s := fmt.Sprintf("%08b", ld.Get("ln").Int())
						k := 1
						for i := 7; i > 1; i-- {
							if s[i] == 49 {
								d.WriteByte(byte(ld.Get(fmt.Sprintf("l%dcv", k)).Int()))
								d.WriteByte(byte(ld.Get(fmt.Sprintf("l%dt", k)).Int() / 5))
								d.WriteByte(byte(ld.Get(fmt.Sprintf("l%dph", k)).Int()))
								d.WriteByte(byte(ld.Get(fmt.Sprintf("l%dos", k)).Int() / 10))
								d.WriteByte(byte(ld.Get(fmt.Sprintf("l%doi", k)).Int() / 10))
								d.WriteByte(byte(ld.Get(fmt.Sprintf("l%dlr", k)).Int()))
								d.WriteByte(byte(ld.Get(fmt.Sprintf("l%dcs", k)).Int() / 10))
								d.WriteByte(byte(ld.Get(fmt.Sprintf("l%dci", k)).Int() / 10))
								d.WriteByte(0)
								d.WriteByte(0)
							}
						}
					case "2600", "5b00":
						d.WriteByte(byte(ld.Get("ln").Int()))
					case "4a01", "4d01", "4d02", "4d03":
						d.WriteByte(gopsu.String2Int8(scmd[2][2:], 16))
						d.WriteByte(byte(ld.Get("ln").Int()))
					case "5c00":
					default:
						getprotocol = false
					}
				case "als":
					br = 5
					rc = 0
					switch scmd[2] {
					case "2500", "2700", "4700", "4800", "4a00":
						d.WriteByte(0)
						d.WriteByte(byte(ld.Get("addr").Int()))
					case "2600", "4600":
					case "3600":
						d.WriteByte(byte(ld.Get("mod").Int()))
					case "3700":
						d.WriteByte(0)
						d.WriteByte(byte(ld.Get("addr").Int()))
						d.WriteByte(byte(ld.Get("mod").Int()))
					case "3800":
						d.WriteByte(0)
						d.WriteByte(byte(ld.Get("addr").Int()))
						d.WriteByte(byte(ld.Get("t").Int() % 256))
						d.WriteByte(byte(ld.Get("t").Int() / 256))
					default:
						getprotocol = false
					}
				case "mru":
					rc = 0x55
					br = byte(ld.Get("br").Int())
					switch scmd[2] {
					case "1100":
						d.WriteByte(byte(ld.Get("addr1").Int()))
						d.WriteByte(byte(ld.Get("addr2").Int()))
						d.WriteByte(byte(ld.Get("addr3").Int()))
						d.WriteByte(byte(ld.Get("addr4").Int()))
						d.WriteByte(byte(ld.Get("addr5").Int()))
						d.WriteByte(byte(ld.Get("addr6").Int()))
						switch ld.Get("ver").Int() {
						case 2:
							d.WriteByte(0x11)
							d.WriteByte(0x04)
							switch ld.Get("type").Int() {
							case 1:
								d.WriteByte(byte(ld.Get("date").Int() + 0x33))
								d.WriteByte(0 + 0x33)
								d.WriteByte(0x15 + 0x33)
								d.WriteByte(0 + 0x33)
							case 2:
								d.WriteByte(byte(ld.Get("date").Int() + 0x33))
								d.WriteByte(0 + 0x33)
								d.WriteByte(0x29 + 0x33)
								d.WriteByte(0 + 0x33)
							case 3:
								d.WriteByte(byte(ld.Get("date").Int() + 0x33))
								d.WriteByte(0 + 0x33)
								d.WriteByte(0x3d + 0x33)
								d.WriteByte(0 + 0x33)
							case 4:
								d.WriteByte(byte(ld.Get("date").Int() + 0x33))
								d.WriteByte(0 + 0x33)
								d.WriteByte(0x01 + 0x33)
								d.WriteByte(0 + 0x33)
							case 5:
								d.WriteByte(byte(ld.Get("date").Int() + 0x33))
								d.WriteByte(0 + 0x33)
								d.WriteByte(0x00 + 0x33)
								d.WriteByte(0 + 0x33)
							}
						case 1:
							d.WriteByte(0x01)
							d.WriteByte(0x02)
							switch ld.Get("type").Int() {
							case 1:
								d.WriteByte(0x34)
								d.WriteByte(0x17)
							case 2:
								d.WriteByte(0x35)
								d.WriteByte(0x17)
							case 3:
								d.WriteByte(0x36)
								d.WriteByte(0x17)
							case 4:
								d.WriteByte(gopsu.String2Int8("00010000", 2) + 0x33)
								d.WriteByte(gopsu.String2Int8(fmt.Sprintf("1001%02b00", ld.Get("date").Int()), 2) + 0x33)
							case 5:
								d.WriteByte(gopsu.String2Int8("00000000", 2) + 0x33)
								d.WriteByte(gopsu.String2Int8(fmt.Sprintf("1001%02b00", ld.Get("date").Int()), 2) + 0x33)
							}
						}
						d.WriteByte(byte(ld.Get("br").Int()))
					case "1300":
						d.WriteByte(byte(ld.Get("addr1").Int()))
						d.WriteByte(byte(ld.Get("addr2").Int()))
						d.WriteByte(byte(ld.Get("addr3").Int()))
						d.WriteByte(byte(ld.Get("addr4").Int()))
						d.WriteByte(byte(ld.Get("addr5").Int()))
						d.WriteByte(byte(ld.Get("addr6").Int()))
						d.WriteByte(0x13)
						d.WriteByte(0x00)
						d.WriteByte(byte(ld.Get("br").Int()))

					default:
						getprotocol = false
					}
				case "esu":
					br = 5
					rc = 2
					switch scmd[2] {
					case "1000": // 复位mcu
						d.WriteByte(0)
					case "1100": // 设置工作参数
						d.WriteByte(byte(ld.Get("wt").Int()))
						d.WriteByte(byte(ld.Get("ot").Int() / 60))
						d.WriteByte(byte(ld.Get("ot").Int() % 60))
						d.WriteByte(byte(ld.Get("ct").Int() / 60))
						d.WriteByte(byte(ld.Get("ct").Int() % 60))
						// 			d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04d",ld.Get("ot").Int())[:2],10))
						// 			d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04d",ld.Get("ot").Int())[2:],10))
						// 			d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04d",ld.Get("ct").Int())[:2],10))
						// 			d.WriteByte(gopsu.String2Int8(fmt.Sprintf("%04d",ld.Get("ct").Int())[2:],10))
						d.WriteByte(0)
						d.WriteByte(0)
						d.WriteByte(0)
					case "1400": // 发送定时调压参数
						for i := 1; i < 9; i++ {
							d.WriteByte(byte(ld.Get(fmt.Sprintf("t%d", i)).Int() / 60))
							d.WriteByte(byte(ld.Get(fmt.Sprintf("t%d", i)).Int() % 60))
							d.WriteByte(byte(ld.Get(fmt.Sprintf("v%d", i)).Int() * 100 % 256))
							d.WriteByte(byte(ld.Get(fmt.Sprintf("v%d", i)).Int() * 100 / 256))
						}
					case "1600": // 对时
						d.Write(GetServerTimeMsg(0, 4, false, true))
						// y, m, dd, h, mm, s, _ := gopsu.SplitDateTime(gopsu.Time2Stamp(ld.Get("date").String()))
						// d.WriteByte(y)
						// d.WriteByte(m)
						// d.WriteByte(dd)
						// d.WriteByte(h)
						// d.WriteByte(mm)
						// d.WriteByte(s)
					case "1700":
						d.WriteByte(byte(ld.Get("no").Int()))
					case "1800": // 手动调压
						d.WriteByte(byte(ld.Get("tv").Int() * 100 % 256))
						d.WriteByte(byte(ld.Get("tv").Int() * 100 / 256))
					case "1900":
						if ld.Get("opt").Int() == 1 {
							d.WriteByte(0x55)
						} else {
							d.WriteByte(0xaa)
						}
					case "2500": // 停运/投运
						if ld.Get("opt").Int() == 1 {
							d.WriteByte(0x55)
						} else {
							d.WriteByte(0xaa)
						}
					case "1d00":
						d.WriteByte(byte(ld.Get("wt").Int()))
						d.WriteByte(byte(ld.Get("ot").Int() / 60))
						d.WriteByte(byte(ld.Get("ot").Int() % 60))
						d.WriteByte(byte(ld.Get("ct").Int() / 60))
						d.WriteByte(byte(ld.Get("ct").Int() % 60))
						d.WriteByte(byte(ld.Get("act").Int() / 5))
						d.WriteByte(byte(ld.Get("bct").Int() / 5))
						d.WriteByte(byte(ld.Get("cct").Int() / 5))
						if ld.Get("tt").Int() == 1 {
							d.WriteByte(0x55)
						} else {
							d.WriteByte(0xaa)
						}
						d.WriteByte(byte(ld.Get("rt").Int()))
						d.WriteByte(byte(ld.Get("stmp").Int()))
						d.WriteByte(byte(ld.Get("ctmp").Int()))
						d.WriteByte(byte(ld.Get("etmp").Int()))
						d.WriteByte(byte(ld.Get("ptmp").Int()))
						d.WriteByte(byte(ld.Get("rtmp").Int()))
						d.WriteByte(byte(ld.Get("iovl").Int() * 100 % 256))
						d.WriteByte(byte(ld.Get("iovl").Int() * 100 / 256))
						d.WriteByte(byte(ld.Get("iuvl").Int() * 100 % 256))
						d.WriteByte(byte(ld.Get("iuvl").Int() * 100 / 256))
						d.WriteByte(byte(ld.Get("oovl").Int() * 100 % 256))
						d.WriteByte(byte(ld.Get("oovl").Int() * 100 / 256))
						d.WriteByte(byte(ld.Get("ouvl").Int() * 100 % 256))
						d.WriteByte(byte(ld.Get("ouvl").Int() * 100 / 256))
						d.WriteByte(byte(ld.Get("sr").Int()))
						d.WriteByte(byte(ld.Get("ppc").Int()))
						if ld.Get("cm").Int() == 1 {
							d.WriteByte(0x55)
						} else {
							d.WriteByte(0xaa)
						}
						if ld.Get("om").Int() == 1 {
							d.WriteByte(0x55)
						} else {
							d.WriteByte(0xaa)
						}
						if ld.Get("aa").Int() == 1 {
							d.WriteByte(0x55)
						} else {
							d.WriteByte(0xaa)
						}
						d.WriteByte(byte(ld.Get("ad").Int()))
						if ld.Get("esm").Int() == 0 {
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
				default:
					getprotocol = false
				}
			case "wxjy":
				switch scmd[1] {
				case "esu":
					switch scmd[2] {
					case "5500", "5600":
						a := ld.Get("ct").String()
						d.WriteByte(gopsu.String2Int8(a[:2], 10))
						d.WriteByte(gopsu.String2Int8(a[2:2], 10))
						d.WriteByte(gopsu.String2Int8(a[4:], 10))
						a = ld.Get("t1").String()
						d.WriteByte(gopsu.String2Int8(a[:2], 10))
						d.WriteByte(gopsu.String2Int8(a[2:], 10))
						d.WriteByte(gopsu.String2Int8(ld.Get("v1").String(), 10))
						a = ld.Get("t2").String()
						d.WriteByte(gopsu.String2Int8(a[:2], 10))
						d.WriteByte(gopsu.String2Int8(a[2:], 10))
						d.WriteByte(gopsu.String2Int8(ld.Get("v2").String(), 10))
						a = ld.Get("t3").String()
						d.WriteByte(gopsu.String2Int8(a[:2], 10))
						d.WriteByte(gopsu.String2Int8(a[2:], 10))
						d.WriteByte(gopsu.String2Int8(ld.Get("v3").String(), 10))
					case "5700":
					default:
						getprotocol = false
					}
				default:
					getprotocol = false
				}
			default:
				getprotocol = false
			}
			if getprotocol && len(cmd) > 0 {
				if len(xaddrs) > 0 {
					var ret byte
					if a := gjson.GetBytes(data, "head.ret"); a.Exists() {
						ret = byte(a.Int())
					} else {
						ret = 0
					}
					for _, v := range xaddrs {
						var ddst string
						if tra == 1 {
							ddst = fmt.Sprintf("%s-%s-%d", scmd[0], scmd[1], v)
						} else if tra == 2 {
							ddst = fmt.Sprintf("%s-rtu-%d", scmd[0], v)
						}
						f := &Fwd{
							DataMsg: DoCommand(byte(gjson.GetBytes(data, "head.ver").Int()), byte(gjson.GetBytes(data, "head.tver").Int()), tra, v, int32(cid), cmd, d.Bytes(), br, rc),
							// DataMsg:  gopsu.Bytes2String(DoCommand(byte(gjson.GetBytes(data, "head.ver").Int()), byte(gjson.GetBytes(data, "head.tver").Int()), tra, v, int32(cid), cmd, d.Bytes(), br, rc), "-"),
							DataDst:  ddst, // fmt.Sprintf("%s.%d", strings.Join(scmd[:2], "."), v),
							DataCmd:  cmd,
							DataSP:   ret,
							DataPT:   500,
							DataType: DataTypeBytes,
							Job:      JobSend,
							Tra:      tra,
							Addr:     v,
							// Src:      fmt.Sprintf("%v", pb2data),
							DstType: 1,
						}
						if cmd == "wlst.rtu.1900" {
							if a := ld.Get("tml_ip"); a.Exists() {
								f.DstIP = a.Int()
							}
						}
						if scmd[0] == "wlst" && scmd[1] == "rtu" && scmd[2][:2] != "70" {
							f.DataPT = 3000
						}
						if tra == 2 {
							f.DataDst = fmt.Sprintf("wlst-rtu-%d", v)
							f.DataPT = 7000
						}
						if scmd[2] == "3100" ||
							scmd[2] == "5800" ||
							scmd[2] == "6800" {
							f.DataPT = 10000
						}
						// 对时命令为适应不同终端，增加不带秒字节的指令一起发
						if cmd == "wlst.rtu.1200" {
							ff := &Fwd{
								DataMsg:  GetServerTimeMsg(v, 1, false, false),
								DataDst:  ddst,
								DataCmd:  cmd,
								DataSP:   ret,
								DataPT:   3000,
								DataType: DataTypeBytes,
								Job:      JobSend,
								Tra:      tra,
								Addr:     v,
								DstType:  1,
							}
							lstf = append(lstf, ff)
						}
						lstf = append(lstf, f)
					}
				}
			}
		}
		if !getprotocol {
			f := &Fwd{
				DataCmd: cmd,
				Src:     fmt.Sprintf("%v", string(data)),
				Ex:      "unknow protocol",
				DstType: byte(gjson.GetBytes(data, "head.src").Int()),
			}
			lstf = append(lstf, f)
		}
	}
	return lstf
}

func dataCtl(data []byte, port *int) (lstf []*Fwd) {
	defer func() {
		if ex := recover(); ex != nil {
			f := &Fwd{
				Ex:  fmt.Sprintf("%+v", errors.WithStack(ex.(error))),
				Src: base64.StdEncoding.EncodeToString(data),
			}
			lstf = append(lstf, f)
		}
	}()
	var pb2data *msgctl.MsgWithCtrl
	pb2data = MsgCtlFromBytes(data)
	// if nob64 {
	// 	pb2data = DecodePb2("", data)
	// } else {
	// 	pb2data = DecodePb2(string(data), nil)
	// }
	if pb2data == nil {
		// f := Fwd{
		//     Ex:  "unknow ctl data",
		//     Src: string(d),
		// }
		// lstf=append(lstf, f)
		return dataCtlJSON(data)
	}
	if pb2data.Head == nil {
		return lstf
	}
	return dataWlst(pb2data, port)
}

func dataWlst(pb2data *msgctl.MsgWithCtrl, port *int) (lstf []*Fwd) {
	defer func() {
		if ex := recover(); ex != nil {
			f := &Fwd{
				Ex: fmt.Sprintf("%+v", errors.WithStack(ex.(error))),
			}
			lstf = append(lstf, f)
		}
	}()

	var zmqmsg []byte
	var ndata []byte
	var ndatacmd string

	getprotocol := true
	cmd := pb2data.Head.Cmd
	tra := byte(pb2data.Head.Tra)
	var br, rc byte
	// if pb2data.Args != nil {
	// 	br = byte(pb2data.Args.Br)
	// 	rc = byte(pb2data.Args.Rc)
	// } else {
	// 	br = byte(5)
	// 	rc = byte(0)
	// }

	switch pb2data.Head.Ver {
	case 1:
		switch pb2data.Head.Mod {
		case 1:
			if pb2data.Head.Cmd == "wlst.sys.socketclose" {
				for _, v := range pb2data.Args.Sims {
					f := &Fwd{
						DataCmd: pb2data.Head.Cmd,
						DataDst: fmt.Sprintf("imei-%d", v),
						Job:     1,
						Src:     fmt.Sprintf("%v", pb2data),
						DstType: byte(pb2data.Head.Src),
						DstIMEI: v,
						// DataMsg: strings.Join(pb2data.Args.Saddr, ","),
					}
					lstf = append(lstf, f)
				}
			} else {
				f := &Fwd{
					DataCmd: pb2data.Head.Cmd,
					DataDst: strconv.FormatInt(int64(pb2data.Head.Src), 10),
					Job:     1,
					Src:     fmt.Sprintf("%v", pb2data),
					DstType: byte(pb2data.Head.Src),
					// DataMsg: strings.Join(pb2data.Args.Saddr, ","),
				}
				if pb2data.Args != nil {
					f.DataMsg = []byte(strings.Join(pb2data.Args.Saddr, ","))
				}
				lstf = append(lstf, f)
				// 记录合法ip
				if CheckLegalIP && len(pb2data.Args.Ip) > 0 {
					if len(pb2data.Args.Ip) > len(LegalIPs) {
						LegalIPs = make([]int64, len(pb2data.Args.Ip))
					}
					copy(LegalIPs, pb2data.Args.Ip)
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
			pb2data.Args.Port = int32(*port)
			pb2data.Head.Code = 0
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
							d.Write(GetServerTimeMsg(0, 1, true, true))
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
				case "hj":
					br = 5
					rc = 0
					switch scmd[2] {
					case "0100": // 设置地址
						d.WriteByte(byte(pb2data.WlstTml.HjLock_0100.NewAddr))
					case "0200": // 读取状态
					case "0300": // 开锁
					case "0400": // 关锁
					case "0500": // 设置启动提醒参数
						d.WriteByte(byte(pb2data.WlstTml.HjLock_0500.FreqLights))
						d.WriteByte(byte(pb2data.WlstTml.HjLock_0500.FreqBeep))
						d.WriteByte(byte(pb2data.WlstTml.HjLock_0500.TimeDelay))
					case "0600": // 添加卡
						d.Write(gopsu.Uint642Bytes(pb2data.WlstTml.HjLock_0600.Card, false)[:4])
					case "0700": // 删除卡
						d.Write(gopsu.Uint642Bytes(pb2data.WlstTml.HjLock_0700.Card, false)[:4])
					case "0800": // 设置管理卡
						d.Write(gopsu.Uint642Bytes(pb2data.WlstTml.HjLock_0800.MasterCard1, false)[:4])
						d.Write(gopsu.Uint642Bytes(pb2data.WlstTml.HjLock_0800.MasterCard1, false)[:4])
					case "0900": // 重启
					case "0a00": // 恢复出厂
					case "0b00": // 读取一个卡号(不做)
					case "0c00": // 设置开锁时间
						d.Write(gopsu.Int642Bytes(int64(pb2data.WlstTml.HjLock_0C00.Delay), false)[:2])
					case "0d00": // 设置是否刷卡主报
						d.WriteByte(byte(pb2data.WlstTml.HjLock_0D00.EnableAlarm))
					default:
						getprotocol = false
					}
				default:
					getprotocol = false
				}
				if getprotocol {
					if scmd[1] == "nbslu" {
						cmdFlag := int32(208 + 55808)
						if len(pb2data.Args.DataFlag) > 0 {
							cmdFlag = pb2data.Args.DataFlag[0] + 55808
						}
						msgnb := &msgnb.MsgNBiot{
							CmdFlag: cmdFlag,
							CmdName: "GoWorkTask"}
						bb := DoCommand(byte(pb2data.Head.Ver), byte(pb2data.Head.Tver), tra, 0, pb2data.Args.Cid, cmd, d.Bytes(), br, rc)
						for _, v := range bb {
							msgnb.RawData = append(msgnb.RawData, int32(v))
						}
						msgnb.Imei = append(msgnb.Imei, pb2data.Args.Sims...)
						if b, ex := pb2.Marshal(msgnb); ex == nil {
							f := &Fwd{
								DataMsg: b,
								// DataMsg:  gopsu.Bytes2String(DoCommand(byte(pb2data.Head.Ver), byte(pb2data.Head.Tver), tra, v, pb2data.Args.Cid, cmd, d.Bytes(), br, rc), "-"),
								DataDst:  fmt.Sprintf("%s-%s", strings.Join(scmd[:2], "-"), "GoWorkTask"),
								DataCmd:  cmd,
								DataSP:   byte(pb2data.Head.Ret),
								DataPT:   3000,
								DataType: DataTypeBytes,
								Job:      JobSend,
								Tra:      tra,
								Addr:     0,
								DstType:  1,
								// Src:      fmt.Sprintf("%v", pb2data),
							}
							if len(pb2data.Args.Sims) > 0 {
								f.DstIMEI = pb2data.Args.Sims[0]
							}
							f.Remark, _ = sjson.Set(f.Remark, "cmdname", "GoWorkTask")
							f.Remark, _ = sjson.Set(f.Remark, "cmdflag", cmdFlag)

							lstf = append(lstf, f)
						}
					} else {
						if len(xaddrs) > 0 {
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
									if len(pb2data.Args.DataFlag) > k {
										f.Remark, _ = sjson.Set(f.Remark, "cmdflag", pb2data.Args.DataFlag[k]+55808)
										f.Remark, _ = sjson.Set(f.Remark, "cmdname", "GoWork")
									} else {
										f.Remark, _ = sjson.Set(f.Remark, "cmdflag", 0xdad0)
										f.Remark, _ = sjson.Set(f.Remark, "cmdname", "GoWork")
									}
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
					}
				}
			case 4:
				pb2data.Head.Src = 1
				pb2data.Head.Mod = 2
				switch cmd {
				case "wlst.gps.0000":
					zm := pb2data.WlstTml.WlstGps_0000
					b, ex := pb2.Marshal(zm)
					if ex == nil {
						zmqmsg = b
					}
					if AnsJSON {
						jv, _ := sjson.Set(JSONData, "head.cmd", cmd)
						jv, _ = sjson.Set(jv, "args.addr.-1", 0)
						jv, _ = sjson.Set(jv, "args.port", *port)
						jv, _ = sjson.Set(jv, "data.date", pb2data.WlstTml.WlstGps_0000.Gpsdate)
						ffj := &Fwd{
							DataCmd:  cmd,
							DataType: DataTypeString,
							DataDst:  "2",
							DstType:  2,
							Tra:      TraDirect,
							Job:      JobSend,
							DataMsg:  []byte(jv),
						}
						lstf = append(lstf, ffj)
					}
					// todo 修改系统时钟
				case "wlst.als.a700":
					zm := pb2data.WlstTml.WlstAlsA700
					b, ex := pb2.Marshal(zm)
					if ex == nil {
						zmqmsg = b
					}
					if AnsJSON {
						jv, _ := sjson.Set(JSONData, "head.cmd", cmd)
						jv, _ = sjson.Set(jv, "args.addr.-1", pb2data.WlstTml.WlstAlsA700.Addr)
						jv, _ = sjson.Set(jv, "args.port", *port)
						jv, _ = sjson.Set(jv, "data.addr", pb2data.WlstTml.WlstAlsA700.Addr)
						jv, _ = sjson.Set(jv, "data.v", pb2data.WlstTml.WlstAlsA700.Lux)
						ffj := &Fwd{
							DataCmd:  cmd,
							DataType: DataTypeString,
							DataDst:  "2",
							DstType:  2,
							Tra:      TraDirect,
							Job:      JobSend,
							DataMsg:  []byte(jv),
						}
						lstf = append(lstf, ffj)
					}
				default:
					getprotocol = false
				}
				if getprotocol {
					f := &Fwd{
						DataCmd:  cmd,
						DataMQ:   zmqmsg,
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
