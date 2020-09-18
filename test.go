package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	// "github.com/tidwall/gjson"

	// "math"
	// "strconv"
	// "time"

	shv1 "./shv1"
	dpv5 "./v5local"
	v6 "./v6"
	jsoniter "github.com/json-iterator/go"
	"github.com/xyzj/gopsu"
	msgctl "gitlab.local/proto/msgjk"
	msgnb "gitlab.local/proto/msgnb"
	msgopen "gitlab.local/proto/msgwlst"
	// "github.com/pkg/errors"
)

var json = jsoniter.Config{
	ObjectFieldMustBeSimpleString: true,
}.Froze()

var dproce = &v6.DataProcessor{
	AreaCode: "1201",
}

// func callrecover() {
//     if ex:=recover();ex!=nil {
//         // e:=errors.Wrap(ex.(error), "aaa")
//         e:=errors.WithStack(ex.(error))
//         e=errors.WithStack(ex.(error))
//         println(fmt.Sprintf("%+v",errors.Wrap(ex.(error), "aaa")))
//         println("-------------")
//         println(fmt.Sprintf("%+v", e))
//     }
// }
// func callrecover2() {
//     if ex:=recover();ex!=nil {
//         println(fmt.Sprintf("%v", ex))
//     }
// }
// func catch(nums ...int) int {
//  defer callrecover2()
// println(fmt.Sprintf("%v", []string{"aaa","bbb"}))
//  println(fmt.Sprintf("%d", nums[1] * nums[2] * nums[3])) //index out of range
//  println("===")
// return 1
// }
//
// func catch2(nums ...int) int {
//  defer callrecover()
//
//  return nums[1] * nums[2] * nums[3] //index out of range
// }
func testTmldata() {
	// defer func() {
	// 	if ex := recover(); ex != nil {
	// 		println(fmt.Sprintf("%+v", errors.WithStack(ex.(error))))
	// 	}
	// }()
	//7e-90-0e-00-07-00-f9-00-02-01-00-01-2c-40-00-00-00-d0-03-22 //// TODO:
	// s := strings.Split("3e-3c-2e-00-30-30-30-30-30-30-30-30-30-30-30-81-55-20-06-00-34-36-30-30-30-37-34-35-33-31-37-34-35-39-30-38-36-37-32-32-33-30-32-37-30-38-38-34-38-33-b7-4b", "-")
	s := strings.Split("68 01 00 00 00 00 00 68 9C 2F 7D 2B 00 00 A3 00 00 00 24 5F 56 5F 56 19 00 14 00 27 02 C1 01 0C 00 03 00 A0 02 00 A8 00 00 0C 0C 00 08 00 00 01 AA 15 00 28 00 00 00 69 FD 54 16", " ")
	s = strings.Split("68 01 00 00 00 00 00 68 9C 0B 7D 07 00 00 A3 00 02 00 20 12 45 18 16", " ")
	s = strings.Split("7e-f3-03-00-da-01-3c-0f-03-00-06-06-03-19-14-05-32-19-14-05-32-19-14-05-32-25-00-25-00-01-01-01-00-00-aa-3c-14-14-14-1e-14-14-14-14-14-14-14-14-14-14-14-14-14-14-14-14-14-14-14-14-01-01-01-01-01-01-01-01-01-01-01-01-ff-00-01-02-03-04-05-00-00-00-00-01-02-0e-0f-0d-00-00-30-0a-db-0a-0a-0a-92-02-02-02-03-03-03-03-03-03-02-02-02-02-02-02-02-02-02-02-02-02-03-03-03-03-25-00-25-00-25-00-25-00-25-00-25-00-aa-00-01-02-00-cb-dd-06-07-08-09-0a-0b-0c-0d-0e-87-20-46-61-69-6c-0d-0a-00-25-00-25-00-25-00-00-00-00-00-25-00-24-37-00-00-00-00-00-00-00-15-00-1f-00-1f-0f-3f-0e-3f-00-3f-00-3f-00-3f-00-3f-01-02-00-3f-02-04-25-00-25-00-25-00-25-00-25-00-25-00-25-00-00-00-00-00-00-00-00-00-25-00-25-00-00-00-00-7e-05-01-00-c1-81-3a-03-01-0a-01-00-69", "-")
	s = strings.Split("FF FE 12 00 87 00 00 64 00 FF FF FF FF FF FF FF FF FF FF FF FF 0F 56 2D", " ")
	//s = gopsu.SplitStringWithLen("68112233445566689C437D3F0100B700383635383233303430393734373833343630303437343938393032323433383938363034353431313139393134323232343308EB0300000C0000008E4FA816", 2)
	//s = strings.Split("68-11-00-11-00-68-eb-01-01-12-01-00-00-0c-70-00-00-20-00-ff-ff-90-ff-29-16-68-17-00-17-00-68-eb-01-01-12-01-00-00-0c-70-00-00-01-01-00-00-00-00-00-00-00-00-90-ff-0d-16-68-19-00-19-00-68-eb-01-01-12-01-00-00-0c-70-00-00-02-02-ee-ee-00-00-00-00-00-00-00-00-90-ff-eb-16-68-c9-00-c9-00-68-eb-01-01-12-01-00-00-0c-70-ff-ff-01-00-27-11-06-09-13-0c-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-90-ff-c0-16-68-50-00-50-00-68-eb-01-01-12-01-00-00-0c-70-00-00-04-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-90-ff-0f-16", "-")
	//s = strings.Split("68-01-00-00-00-00-00-68-9c-43-7d-3f-01-00-b7-00-38-36-37-37-32-36-30-33-31-39-30-31-31-36-30-34-36-30-31-31-33-30-34-36-30-36-32-37-32-32-38-39-38-36-31-31-31-39-32-36-34-30-30-36-30-34-30-30-33-33-35-91-02-00-80-b5-00-00-00-3e-b9-24-16", "-")
	// s = strings.Split("68 19 00 19 00 68 A8 01 01 42 16 00 00 0A 61 00 00 04 01 00 1D 3A D0 07 00 71 35 54 0B DC 0D 8E 16", " ")

	ss := make([]byte, len(s))
	for k, v := range s {
		ss[k] = gopsu.String2Int8(v, 16)
	}
	// js := "aAd2GQAAAGickH2MAQC5ADCRDlUAAAAAAACiAAAAAAAAACgIAAAAAAAAGwsAAAAAAADHDQAAAAAAABUBAAAAAAAACBwAAAAAAAAAAAAAAAAAAAAAAAFkZGRkEwgHDDI6bDcAACIPAABVAPoA+gD6APoABhoDAIDWAgCAaAAAAFMAAABtAACAFAAAAMgJAAAAFAQdAAYBEyh3aZoW"
	// sa, err := base64.StdEncoding.DecodeString(js)
	// if err != nil {
	// 	println(err.Error())
	// 	return
	// }
	// ss = sa
	println("-=+", gopsu.Bytes2String(ss, "-"))
	// a := int64(0)
	// b := true
	// c := 0
	// t := false
	// r := dpv5.ClassifyTmlData(ss, &a, &c, &c, &b, 193)
	r := v6.ClassifyTmlData(ss, int64(01), time.Now().Unix(), "abcd")
	// ss, _ = base64.StdEncoding.DecodeString("aAcglgAAAGickH2MAQC5AHGRTVtNWwAAAABZAOEAAAAAAFMHYBMAAAAAhAPTBgAAAAAgCIoUAAAAAMMA3AEAAAAAzhgAzhgAAAAAAAAAAAAAAAAAAABkZAAAEwsBAQMQbAAAACIAAABVA/oA+gD6APoABskCAICOAgCArgAAAOoAAABsAACA5gAAAMkJAAAAGAQLAAcHETbtksgW")
	// r := dproce.ProcessTml(ss)
	// fmt.Printf("%+v\n\n", r)
	// println(r.Ex)
	if len(r.Ex) > 0 {
		println("err: ", r.Ex)
	}
	for k, v := range r.Do {
		//		println(fmt.Sprintf("--- %d: %+v", k, v))
		// println(fmt.Sprintf(" --- %d %+v \n", k, v))
		if len(v.Ex) > 0 {
			println("err-----------------------------------------------------------------", v.Ex, v.Src)
		} else {
			// println(fmt.Sprintf("%d, %+v", k, v))
			// msg := &msgctl.WlstSlu_9D00{}
			// // proto.Unmarshal(v.DataMQ, msg)
			// msg.Unmarshal(v.DataMQ)

			// println("---mq---", msg.String(), string(gopsu.PB2Json(msg)))
			// println(k, msg.String())
			// z := v6.MsgCtlFromBytes(v.DataMsg)
			if strings.Contains(v.DataCmd, "open") { // 国标
				msg := &msgopen.MsgGBOpen{}
				err := msg.Unmarshal(v.DataMsg)
				if err != nil {
					println(fmt.Sprintf("--- %d, %s", k, gopsu.Bytes2String(v.DataMsg, "-")))
				} else {
					println(fmt.Sprintf("=== %d, %s", k, msg.String()))
				}
			} else if strings.Contains(v.DataCmd, "nbupg") {
				msg := &msgnb.MsgNBOpen{}
				err := msg.Unmarshal(v.DataMsg)
				if err != nil {
					println(fmt.Sprintf("--- %d, %s", k, gopsu.Bytes2String(v.DataMsg, "-")))
				} else {
					println(fmt.Sprintf("=== %d, %s", k, gopsu.PB2Json(msg)))
				}
			} else {
				z := dpv5.MsgCtlFromBytes(v.DataMsg)
				if z == nil {
					println(fmt.Sprintf("--- %d, %+v", k, v.DataMsg))
				} else {
					// println(fmt.Sprintf("--- %d, %+v", k, string(pb2json(z))))
					println(fmt.Sprintf("=== %d, %s", k, gopsu.PB2Json(z)))
				}
			}
		}
	}
}

func testTmldataNB() {
	// defer func() {
	// 	if ex := recover(); ex != nil {
	// 		println(fmt.Sprintf("%+v", errors.WithStack(ex.(error))))
	// 	}
	// }()
	//7e-90-0e-00-07-00-f9-00-02-01-00-01-2c-40-00-00-00-d0-03-22 //// TODO:
	// s := strings.Split("3e-3c-2e-00-30-30-30-30-30-30-30-30-30-30-30-81-55-20-06-00-34-36-30-30-30-37-34-35-33-31-37-34-35-39-30-38-36-37-32-32-33-30-32-37-30-38-38-34-38-33-b7-4b", "-")
	s := strings.Split("68 01 00 00 00 00 00 68 9C 2F 7D 2B 00 00 A3 00 00 00 24 5F 56 5F 56 19 00 14 00 27 02 C1 01 0C 00 03 00 A0 02 00 A8 00 00 0C 0C 00 08 00 00 01 AA 15 00 28 00 00 00 69 FD 54 16", " ")
	s = strings.Split("68 01 00 00 00 00 00 68 9C 0B 7D 07 00 00 A3 00 02 00 20 12 45 18 16", " ")
	s = strings.Split("7e-f3-03-00-da-01-3c-0f-03-00-06-06-03-19-14-05-32-19-14-05-32-19-14-05-32-25-00-25-00-01-01-01-00-00-aa-3c-14-14-14-1e-14-14-14-14-14-14-14-14-14-14-14-14-14-14-14-14-14-14-14-14-01-01-01-01-01-01-01-01-01-01-01-01-ff-00-01-02-03-04-05-00-00-00-00-01-02-0e-0f-0d-00-00-30-0a-db-0a-0a-0a-92-02-02-02-03-03-03-03-03-03-02-02-02-02-02-02-02-02-02-02-02-02-03-03-03-03-25-00-25-00-25-00-25-00-25-00-25-00-aa-00-01-02-00-cb-dd-06-07-08-09-0a-0b-0c-0d-0e-87-20-46-61-69-6c-0d-0a-00-25-00-25-00-25-00-00-00-00-00-25-00-24-37-00-00-00-00-00-00-00-15-00-1f-00-1f-0f-3f-0e-3f-00-3f-00-3f-00-3f-00-3f-01-02-00-3f-02-04-25-00-25-00-25-00-25-00-25-00-25-00-25-00-00-00-00-00-00-00-00-00-25-00-25-00-00-00-00-7e-05-01-00-c1-81-3a-03-01-0a-01-00-69", "-")
	s = strings.Split("68 0E 00 0E 00 68 0B 01 01 12 04 00 00 00 60 00 00 01 00 02 86 16", " ")
	s = gopsu.SplitStringWithLen("68112233445566689C377D330100210000660014051C0B2C050B16212C0000550000121106000076657220302E3100000000000000000000000000090C111A430A2616", 2)
	//s = strings.Split("68-11-00-11-00-68-eb-01-01-12-01-00-00-0c-70-00-00-20-00-ff-ff-90-ff-29-16-68-17-00-17-00-68-eb-01-01-12-01-00-00-0c-70-00-00-01-01-00-00-00-00-00-00-00-00-90-ff-0d-16-68-19-00-19-00-68-eb-01-01-12-01-00-00-0c-70-00-00-02-02-ee-ee-00-00-00-00-00-00-00-00-90-ff-eb-16-68-c9-00-c9-00-68-eb-01-01-12-01-00-00-0c-70-ff-ff-01-00-27-11-06-09-13-0c-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-90-ff-c0-16-68-50-00-50-00-68-eb-01-01-12-01-00-00-0c-70-00-00-04-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-90-ff-0f-16", "-")
	s = strings.Split("FF-FE-12-00-87-00-00-64-00-FF-FF-FF-FF-FF-FF-FF-FF-FF-FF-FF-FF-0F-56-2D", "-")
	s = strings.Split("68-68-27-29-93-90-01-68-9c-0b-7d-07-00-00-a3-00-02-00-00-13-9d-2c-16", "-")
	// s = strings.Split("68 19 00 19 00 68 A8 01 01 42 16 00 00 0A 61 00 00 04 01 00 1D 3A D0 07 00 71 35 54 0B DC 0D 8E 16", " ")

	ss := make([]byte, len(s))
	for k, v := range s {
		ss[k] = gopsu.String2Int8(v, 16)
	}
	// js := "aAd2GQAAAGickH2MAQC5ADCRDlUAAAAAAACiAAAAAAAAACgIAAAAAAAAGwsAAAAAAADHDQAAAAAAABUBAAAAAAAACBwAAAAAAAAAAAAAAAAAAAAAAAFkZGRkEwgHDDI6bDcAACIPAABVAPoA+gD6APoABhoDAIDWAgCAaAAAAFMAAABtAACAFAAAAMgJAAAAFAQdAAYBEyh3aZoW"
	// sa, err := base64.StdEncoding.DecodeString(js)
	// if err != nil {
	// 	println(err.Error())
	// 	return
	// }
	// ss = sa
	println("-=+", gopsu.Bytes2String(ss, "-"))
	// a := int64(0)
	// b := true
	// c := 0
	// t := false
	//r := dpv5.ClassifyTmlData(ss, &a, &c, &c, &b, 193)
	// r := v6.ClassifyTmlData(ss, 0, 0)
	// ss, _ = base64.StdEncoding.DecodeString("aAcglgAAAGickH2MAQC5AHGRTVtNWwAAAABZAOEAAAAAAFMHYBMAAAAAhAPTBgAAAAAgCIoUAAAAAMMA3AEAAAAAzhgAzhgAAAAAAAAAAAAAAAAAAABkZAAAEwsBAQMQbAAAACIAAABVA/oA+gD6APoABskCAICOAgCArgAAAOoAAABsAACA5gAAAMkJAAAAGAQLAAcHETbtksgW")
	r := dproce.ProcessTml(ss)
	// fmt.Printf("%+v\n\n", r)
	// println(r.Ex)
	if len(r.Ex) > 0 {
		println("err: ", r.Ex)
	}
	for k, v := range r.Do {
		//		println(fmt.Sprintf("--- %d: %+v", k, v))
		println(fmt.Sprintf(" --- %d %+v \n", k, v))
		if len(v.Ex) > 0 {
			println("err-----------------------------------------------------------------", v.Ex, v.Src)
		} else {
			// println(fmt.Sprintf("%d, %+v", k, v))
			// msg := &msgctl.WlstSlu_9D00{}
			// // proto.Unmarshal(v.DataMQ, msg)
			// msg.Unmarshal(v.DataMQ)

			// println("---mq---", msg.String(), string(gopsu.PB2Json(msg)))
			// println(k, msg.String())
			// z := v6.MsgCtlFromBytes(v.DataMsg)
			if strings.Contains(v.DataCmd, "open") { // 国标
				msg := &msgopen.MsgGBOpen{}
				err := msg.Unmarshal(v.DataMsg)
				if err != nil {
					println(fmt.Sprintf("--- %d, %s", k, gopsu.Bytes2String(v.DataMsg, "-")))
				} else {
					println(fmt.Sprintf("=== %d, %s", k, msg.String()))
				}
			} else {
				z := dpv5.MsgCtlFromBytes(v.DataMsg)
				if z == nil {
					println(fmt.Sprintf("--- %d, %+v", k, v.DataMsg))
				} else {
					// println(fmt.Sprintf("--- %d, %+v", k, string(pb2json(z))))
					println(fmt.Sprintf("=== %d, %s", k, gopsu.PB2Json(z)))
				}
			}
		}
	}
}

func testTmldataV6() {
	msg := &v6.DataProcessor{}
	s := strings.Split("7e-3a-d3-06-a0-44-32-00-00-00-00-41-31-00-00-00-00-44-32-00-00-00-00-44-32-61-13-70-0e-41-31-31-46-26-34-44-32-9e-0d-4c-0a-07-00-00-00-00-03-68-26-13-1e-00-00-00-00-00-50-44-80-00-75-77", "-")

	ss := make([]byte, len(s))
	for k, v := range s {
		ss[k] = gopsu.String2Int8(v, 16)
	}

	println("-=+", gopsu.Bytes2String(ss, "-"))

	z := msg.ProcessTml(ss)
	println(fmt.Sprintf("%+v", z))
	for k, v := range z.Do {
		if strings.Contains(v.DataCmd, "open") { // 国标
			msg := &msgopen.MsgGBOpen{}
			err := msg.Unmarshal(v.DataMsg)
			if err != nil {
				println(fmt.Sprintf("--- %d, %s", k, gopsu.Bytes2String(v.DataMsg, "-")))
			} else {
				println(fmt.Sprintf("=== %d, %s", k, msg.String()))
			}
		} else {
			z := v6.MsgCtlFromBytes(v.DataMsg)
			if z == nil {
				println(fmt.Sprintf("--- %d, %+v", k, v.DataMsg))
			} else {
				// println(fmt.Sprintf("--- %d, %+v", k, string(pb2json(z))))
				println(fmt.Sprintf("=== %d, %s", k, gopsu.PB2Json(z)))
			}
		}
	}
}

func testCtldatajson() {
	a := 0
	t := true
	// f := false
	dpv5.AnsJSON = t
	// dpv5.EnableCustomTimer = f
	js := `{"head":{"mod":2,"src":2,"ver":1,"tra":1,"tver":1,"cmd":"wlst.rtu.4101","gid":0,"rcv":0,"ret":0},"args":{"port":10606,"addr":[826],"cid":0,"scid":0},"data":{"ln":12,"vr":300,"l1":100,"l2":100,"l3":100,"l4":100,"l5":100,"l6":100,"l7":100,"l8":100,"l9":100,"l10":100,"l11":100,"l12":100,"l13":0,"l14":0,"l15":0,"l16":0,"l17":0,"l18":0,"l19":0,"l20":0,"l21":0,"l22":0,"l23":0,"l24":0,"l25":0,"l26":0,"l27":0,"l28":0,"l29":0,"l30":0,"l31":0,"l32":0,"l33":0,"l34":0,"l35":0,"l36":0,"l37":0,"l38":0,"l39":0,"l40":0,"l41":0,"l42":0,"l43":0,"l44":0,"l45":0,"l46":0,"l47":0,"l48":0}}`

	r := dpv5.ClassifyCtlData([]byte(fmt.Sprintf("`%s`", js)), &a)

	for k, v := range r.Do {
		println(fmt.Sprintf("%d: %+v", k, v))
	}
	println(fmt.Sprintf("%+v", r))
	println("done.")
}

func f() (result int) {
	defer func() {
		result++
	}()
	return 0
}
func pb2json(pb interface{}) []byte {
	jsonBytes, err := json.Marshal(pb)
	if err != nil {
		return nil
	}
	return jsonBytes
}

func testCtldataPb2() {
	t := true
	// f := false
	dpv5.AnsJSON = t
	// dpv5.EnableCustomTimer = f
	a := 10001
	msg := &msgctl.MsgWithCtrl{
		Head: &msgctl.Head{
			Mod:  2,
			Src:  2,
			Ver:  1,
			Tver: 1,
			Ret:  1,
			Cmd:  "wlst.elu.6259",
			Tra:  1,
		},
		Args: &msgctl.Args{
			Port: 1024,
			Addr: []int64{1},
		},
		WlstTml: &msgctl.WlstTerminal{
			WlstRtu_7020: &msgctl.WlstRtu_70A0{
				CmdType: 1,
			},
			// WlstRtuDc00: &msgctl.WlstRtuDc00{
			// 	Ver: "---",
			// },
		},
		Syscmds: &msgctl.SysCommands{},
	}
	msg.WlstCom_3E01 = &msgctl.WlstCom_3E01{
		ArgsMark:  []int32{7, 0, 255, 1, 1, 0, 3, 8, 1, 0, 16, 15},
		GroupMark: 63,
	}
	var js string
	js = base64.StdEncoding.EncodeToString(dpv5.CodePb2(msg))
	// js = "ChsIAhACGAEgASgBMAE6DXdsc3QucnR1LjEyMDASBhCACBoBAqIGGsIBFwoVMjAxOS0wMS0zMCAxNToyNDo0NyAz"
	// js = "CiAIAhAGGAEwAToNd2xzdC5jb20uM2UwMkEAAAB0Z2rkQRIDGgEE0j55EBsaCQEAhwEBAwgBACIiCiBjbW5ldAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACoUEgi0AacB9QHpARiFnQEoAUgFUHg6IQgBEgsxODkwMDAwMDAwMBoQQ1hMTAAAAAAAAAAAAAAAAEINCgsxODkwMDAwMDAwMA=="

	r := dpv5.ClassifyCtlData([]byte(fmt.Sprintf("`%s`", js)), &a)
	println(fmt.Sprintf("%+v", r))
	for k, v := range r.Do {
		// println(fmt.Sprintf("%d: %+v", k, v))
		println(k, v.DataSP, gopsu.Bytes2String(v.DataMsg, "-"))
	}
}

func testCtldata() {
	t := true
	// f := false
	dpv5.AnsJSON = t
	// dpv5.EnableCustomTimer = f
	a := 10001
	var s = "`{\"head\": {\"src\": 2, \"gid\": 0, \"ver\": 1, \"tver\": 1, \"tra\": 1, \"rcv\": 0, \"cmd\": \"wlst.rtu.2000\", \"mod\": 2}, \"args\": {\"port\": 1024, \"addr\": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 550, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 567, 568, 569, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591, 592, 593, 59"
	s = `{"head":{"mod":2,"src":2,"ver":1,"tver":1,"tra":1,"ret":1,"cmd":"wlst.slu.7c00"},"args":{"port":51002,"addr":[3]},"wlst_tml":{"wlst_slu_7c00":{"cmd_idx":1,"addr_type":3,"addr":1,"add_or_update":1,"operation_data":[{"operation_type":1,"cmd_type":4,"week_set":[1,0,1,1,1,0,1],"timer_or_offset":1055,"cmd_mix":[1,1,0,0],"cmd_pwm":{"rate":400}},{"operation_type":1,"cmd_type":4,"week_set":[1,0,1,1,1,0,1],"timer_or_offset":1260,"cmd_mix":[4,4,0,0],"cmd_pwm":{"rate":400}},{"operation_type":1,"cmd_type":5,"week_set":[1,0,1,1,1,0,1],"timer_or_offset":568,"cmd_mix":[0,0],"cmd_pwm":{"loop_can_do":[1,2],"scale":59,"rate":400}}]}}}`
	z := dpv5.ClassifyCtlData([]byte("`"+s+"`"), &a)
	println(fmt.Sprintf("%+v", string(z.Unfinish)))
	for k, v := range z.Do {
		println(fmt.Sprintf("%d: %+v", k, v))
	}
}

func testCtldataV6() {
	msg := &v6.DataProcessor{}
	var s = `ChsIAhACGAEgASgBMAE6DXdsc3Quc2x1LjdjMDASBxC6jgMaAQOiBmjqJ2UIARADGAEgAygBMhsIARAEGgcBAAEBAQABIJ8IKgQBAQAAMgMYkAMyGwgBEAQaBwEAAQEBAAEg7AkqBAQEAAAyAxiQAzIfCAEQBRoHAQABAQEAASC4BCoCAAAyCQoCAQIQOxiQAw==`
	ss, _ := base64.StdEncoding.DecodeString(s)
	b := []byte(ss)
	z := msg.ProcessCtl(&b)
	println(fmt.Sprintf("%+v", z))
	for k, v := range z {
		println(fmt.Sprintf("%d: %+v", k, v))
	}
}

func countCRC() {
	// 7e-e-3f-0-37-5-0-7e-62-2-1-59-73-d8-0-90-0-90,0
	bb := []byte{0x7e, 0x62, 0x02, 0x0, 0x59}
	// bb := []byte{0x7e, 0x62, 0x2, 0x1, 0x59}
	bbb := gopsu.CountCrc16VB(&bb)
	bb = append(bb, bbb...)
	println(gopsu.Bytes2String(bb, "-"))
}
func aaa(a ...interface{}) {
	r := strings.NewReplacer("[", "", "]", "")
	println(r.Replace((fmt.Sprintf("%+v", a))))
}

func tmlshv1data() {
	dp := &shv1.DataProcessor{}
	s := "68-0e-00-0e-00-68-01-00-00-00-00-00-00-00-c2-73-00-00-01-00-bf-79-16"
	s =  "68-12-00-12-00-68-30-30-30-30-30-30-30-30-c0-01-08-00-02-78-00-00-01-00-29-16-16"
	a := dp.ParseTml(gopsu.String2Bytes(s, "-"))
	println(fmt.Sprintf("%+v", a))
	for k, v := range a.Do {
		println(k, fmt.Sprintf("%+v", v))
	}
}
func main() {
	tmlshv1data()
	// s := "CikIARABGAEgASgBMAE6E3dsc3Quc3lzLm9ubGluZWluZm9IAnj3z/f2BRIAGp83MkIIwNHKmQUSDHdsc3QtbGR1LTEwNRIMd2xzdC1zbHUtMTA1Egx3bHN0LWFscy0xMDUSDHdsc3QtcnR1LTEwNSAWKGkyQgjA0cqZBRIMd2xzdC1hbHMtMTIxEgx3bHN0LXJ0dS0xMjESDHdsc3QtbGR1LTEyMRIMd2xzdC1zbHUtMTIxIBYoeTJDCMDRypkFEgx3bHN0LXNsdS0xODMSDHdsc3QtYWxzLTE4MxIMd2xzdC1ydHUtMTgzEgx3bHN0LWxkdS0xODMgFii3ATJDCMDRypkFEgx3bHN0LWFscy0xODUSDHdsc3QtcnR1LTE4NRIMd2xzdC1sZHUtMTg1Egx3bHN0LXNsdS0xODUgFii5ATJDCMDRypkFEgx3bHN0LWxkdS0xODgSDHdsc3Qtc2x1LTE4OBIMd2xzdC1hbHMtMTg4Egx3bHN0LXJ0dS0xODggFii8ATJCCMDRypkFEgx3bHN0LWFscy0xMDMSDHdsc3QtcnR1LTEwMxIMd2xzdC1sZHUtMTAzEgx3bHN0LXNsdS0xMDMgFihnMkIIwNHKmQUSDHdsc3QtbGR1LTEyNxIMd2xzdC1zbHUtMTI3Egx3bHN0LWFscy0xMjcSDHdsc3QtcnR1LTEyNyAWKH8yQwjA0cqZBRIMd2xzdC1sZHUtMTc1Egx3bHN0LXNsdS0xNzUSDHdsc3QtYWxzLTE3NRIMd2xzdC1ydHUtMTc1IBYorwEyQwjA0cqZBRIMd2xzdC1hbHMtMTc4Egx3bHN0LXJ0dS0xNzgSDHdsc3QtbGR1LTE3OBIMd2xzdC1zbHUtMTc4IBYosgEyQgjA0cqZBRIMd2xzdC1hbHMtMTEyEgx3bHN0LXJ0dS0xMTISDHdsc3QtbGR1LTExMhIMd2xzdC1zbHUtMTEyIBYocDJDCMDRypkFEgx3bHN0LWxkdS0xODQSDHdsc3Qtc2x1LTE4NBIMd2xzdC1hbHMtMTg0Egx3bHN0LXJ0dS0xODQgFii4ATIZCN3l+vMKEgt3bHN0LXJ0dS0xMRgEIBgoCzJDCMDRypkFEgx3bHN0LXNsdS0xMzMSDHdsc3QtYWxzLTEzMxIMd2xzdC1ydHUtMTMzEgx3bHN0LWxkdS0xMzMgFiiFATIYCN/R+e8OEg13bHN0LXJ0dS01MTE0KPonMkIIwNHKmQUSDHdsc3QtbGR1LTExMxIMd2xzdC1zbHUtMTEzEgx3bHN0LWFscy0xMTMSDHdsc3QtcnR1LTExMyAWKHEyQwjA0cqZBRIMd2xzdC1sZHUtMTY4Egx3bHN0LXNsdS0xNjgSDHdsc3QtYWxzLTE2OBIMd2xzdC1ydHUtMTY4IBYoqAEyQwjA0cqZBRIMd2xzdC1hbHMtMTczEgx3bHN0LXJ0dS0xNzMSDHdsc3QtbGR1LTE3MxIMd2xzdC1zbHUtMTczIBYorQEyQwjA0cqZBRIMd2xzdC1sZHUtMjAwEgx3bHN0LXNsdS0yMDASDHdsc3QtYWxzLTIwMBIMd2xzdC1ydHUtMjAwIBYoyAEyKwinoMbgBBINd2xzdC1sZHUtNTExMhINd2xzdC1ydHUtNTExMhgCIBso+CcyQgjA0cqZBRIMd2xzdC1sZHUtMTE4Egx3bHN0LXNsdS0xMTgSDHdsc3QtYWxzLTExOBIMd2xzdC1ydHUtMTE4IBYodjJDCMDRypkFEgx3bHN0LXNsdS0xNDkSDHdsc3QtYWxzLTE0ORIMd2xzdC1ydHUtMTQ5Egx3bHN0LWxkdS0xNDkgFiiVATJDCMDRypkFEgx3bHN0LWxkdS0xNTUSDHdsc3Qtc2x1LTE1NRIMd2xzdC1hbHMtMTU1Egx3bHN0LXJ0dS0xNTUgFiibATJDCMDRypkFEgx3bHN0LWFscy0xNjASDHdsc3QtcnR1LTE2MBIMd2xzdC1sZHUtMTYwEgx3bHN0LXNsdS0xNjAgFiigATJDCMDRypkFEgx3bHN0LWFscy0xMzQSDHdsc3QtcnR1LTEzNBIMd2xzdC1sZHUtMTM0Egx3bHN0LXNsdS0xMzQgFiiGATJCCMDRypkFEgx3bHN0LWxkdS0xMDISDHdsc3Qtc2x1LTEwMhIMd2xzdC1hbHMtMTAyEgx3bHN0LXJ0dS0xMDIgFihmMkIIwNHKmQUSDHdsc3QtYWxzLTEyMhIMd2xzdC1ydHUtMTIyEgx3bHN0LWxkdS0xMjISDHdsc3Qtc2x1LTEyMiAWKHoyQwjA0cqZBRIMd2xzdC1hbHMtMTUzEgx3bHN0LXJ0dS0xNTMSDHdsc3QtbGR1LTE1MxIMd2xzdC1zbHUtMTUzIBYomQEyQwjA0cqZBRIMd2xzdC1zbHUtMTY5Egx3bHN0LWFscy0xNjkSDHdsc3QtcnR1LTE2ORIMd2xzdC1sZHUtMTY5IBYoqQEyQwjA0cqZBRIMd2xzdC1sZHUtMTg3Egx3bHN0LXNsdS0xODcSDHdsc3QtYWxzLTE4NxIMd2xzdC1ydHUtMTg3IBYouwEyQgjA0cqZBRIMd2xzdC1sZHUtMTA0Egx3bHN0LXNsdS0xMDQSDHdsc3QtYWxzLTEwNBIMd2xzdC1ydHUtMTA0IBYoaDJDCMDRypkFEgx3bHN0LWxkdS0xMzASDHdsc3Qtc2x1LTEzMBIMd2xzdC1hbHMtMTMwEgx3bHN0LXJ0dS0xMzAgFiiCATJDCMDRypkFEgx3bHN0LXNsdS0xMzESDHdsc3QtYWxzLTEzMRIMd2xzdC1ydHUtMTMxEgx3bHN0LWxkdS0xMzEgFiiDATJDCMDRypkFEgx3bHN0LWxkdS0xNDQSDHdsc3Qtc2x1LTE0NBIMd2xzdC1hbHMtMTQ0Egx3bHN0LXJ0dS0xNDQgFiiQATJDCMDRypkFEgx3bHN0LXJ0dS0xNTESDHdsc3QtbGR1LTE1MRIMd2xzdC1zbHUtMTUxEgx3bHN0LWFscy0xNTEgFiiXATJDCMDRypkFEgx3bHN0LWxkdS0xNTQSDHdsc3Qtc2x1LTE1NBIMd2xzdC1hbHMtMTU0Egx3bHN0LXJ0dS0xNTQgFiiaATJDCMDRypkFEgx3bHN0LWxkdS0xOTQSDHdsc3Qtc2x1LTE5NBIMd2xzdC1hbHMtMTk0Egx3bHN0LXJ0dS0xOTQgFijCATJDCMDRypkFEgx3bHN0LWxkdS0xOTUSDHdsc3Qtc2x1LTE5NRIMd2xzdC1hbHMtMTk1Egx3bHN0LXJ0dS0xOTUgFijDATJCCMDRypkFEgx3bHN0LXNsdS0xMjUSDHdsc3QtYWxzLTEyNRIMd2xzdC1ydHUtMTI1Egx3bHN0LWxkdS0xMjUgFih9MkMIwNHKmQUSDHdsc3QtbGR1LTE2NBIMd2xzdC1zbHUtMTY0Egx3bHN0LWFscy0xNjQSDHdsc3QtcnR1LTE2NCAWKKQBMkMIwNHKmQUSDHdsc3QtbGR1LTE4MRIMd2xzdC1zbHUtMTgxEgx3bHN0LWFscy0xODESDHdsc3QtcnR1LTE4MSAWKLUBMkMIwNHKmQUSDHdsc3QtbGR1LTE5ORIMd2xzdC1zbHUtMTk5Egx3bHN0LWFscy0xOTkSDHdsc3QtcnR1LTE5OSAWKMcBMkMIwNHKmQUSDHdsc3Qtc2x1LTEzNhIMd2xzdC1hbHMtMTM2Egx3bHN0LXJ0dS0xMzYSDHdsc3QtbGR1LTEzNiAWKIgBMkIIwNHKmQUSDHdsc3QtcnR1LTEwOBIMd2xzdC1sZHUtMTA4Egx3bHN0LXNsdS0xMDgSDHdsc3QtYWxzLTEwOCAWKGwyQgjA0cqZBRIMd2xzdC1ydHUtMTA5Egx3bHN0LWxkdS0xMDkSDHdsc3Qtc2x1LTEwORIMd2xzdC1hbHMtMTA5IBYobTJDCMDRypkFEgx3bHN0LXNsdS0xNTISDHdsc3QtYWxzLTE1MhIMd2xzdC1ydHUtMTUyEgx3bHN0LWxkdS0xNTIgFiiYATJDCMDRypkFEgx3bHN0LWxkdS0xNzISDHdsc3Qtc2x1LTE3MhIMd2xzdC1hbHMtMTcyEgx3bHN0LXJ0dS0xNzIgFiisATJDCMDRypkFEgx3bHN0LXNsdS0xOTYSDHdsc3QtYWxzLTE5NhIMd2xzdC1ydHUtMTk2Egx3bHN0LWxkdS0xOTYgFijEATJDCMDRypkFEgx3bHN0LXNsdS0xMjkSDHdsc3QtYWxzLTEyORIMd2xzdC1ydHUtMTI5Egx3bHN0LWxkdS0xMjkgFiiBATJDCMDRypkFEgx3bHN0LWxkdS0xMzISDHdsc3Qtc2x1LTEzMhIMd2xzdC1hbHMtMTMyEgx3bHN0LXJ0dS0xMzIgFiiEATJDCMDRypkFEgx3bHN0LWxkdS0xMzcSDHdsc3Qtc2x1LTEzNxIMd2xzdC1hbHMtMTM3Egx3bHN0LXJ0dS0xMzcgFiiJATJDCMDRypkFEgx3bHN0LWFscy0xMzkSDHdsc3QtcnR1LTEzORIMd2xzdC1sZHUtMTM5Egx3bHN0LXNsdS0xMzkgFiiLATJCCMDRypkFEgx3bHN0LWxkdS0xMTUSDHdsc3Qtc2x1LTExNRIMd2xzdC1hbHMtMTE1Egx3bHN0LXJ0dS0xMTUgFihzMkMIwNHKmQUSDHdsc3QtYWxzLTEzOBIMd2xzdC1ydHUtMTM4Egx3bHN0LWxkdS0xMzgSDHdsc3Qtc2x1LTEzOCAWKIoBMkMIwNHKmQUSDHdsc3QtYWxzLTE2NhIMd2xzdC1ydHUtMTY2Egx3bHN0LWxkdS0xNjYSDHdsc3Qtc2x1LTE2NiAWKKYBMkMIwNHKmQUSDHdsc3Qtc2x1LTE5NxIMd2xzdC1hbHMtMTk3Egx3bHN0LXJ0dS0xOTcSDHdsc3QtbGR1LTE5NyAWKMUBMkMIwNHKmQUSDHdsc3QtbGR1LTE1MBIMd2xzdC1zbHUtMTUwEgx3bHN0LWFscy0xNTASDHdsc3QtcnR1LTE1MCAWKJYBMkMIwNHKmQUSDHdsc3QtbGR1LTE4MBIMd2xzdC1zbHUtMTgwEgx3bHN0LWFscy0xODASDHdsc3QtcnR1LTE4MCAWKLQBMkMIwNHKmQUSDHdsc3QtbGR1LTE4NhIMd2xzdC1zbHUtMTg2Egx3bHN0LWFscy0xODYSDHdsc3QtcnR1LTE4NiAWKLoBMkIIwNHKmQUSDHdsc3QtbGR1LTEwMRIMd2xzdC1zbHUtMTAxEgx3bHN0LWFscy0xMDESDHdsc3QtcnR1LTEwMSAWKGUyQgjA0cqZBRIMd2xzdC1zbHUtMTE3Egx3bHN0LWFscy0xMTcSDHdsc3QtcnR1LTExNxIMd2xzdC1sZHUtMTE3IBYodTJDCMDRypkFEgx3bHN0LWFscy0xMzUSDHdsc3QtcnR1LTEzNRIMd2xzdC1sZHUtMTM1Egx3bHN0LXNsdS0xMzUgFiiHATJCCMDRypkFEgx3bHN0LWxkdS0xMjQSDHdsc3Qtc2x1LTEyNBIMd2xzdC1hbHMtMTI0Egx3bHN0LXJ0dS0xMjQgFih8MkMIwNHKmQUSDHdsc3QtbGR1LTE0OBIMd2xzdC1zbHUtMTQ4Egx3bHN0LWFscy0xNDgSDHdsc3QtcnR1LTE0OCAWKJQBMkMIwNHKmQUSDHdsc3Qtc2x1LTE2MRIMd2xzdC1hbHMtMTYxEgx3bHN0LXJ0dS0xNjESDHdsc3QtbGR1LTE2MSAWKKEBMkMIwNHKmQUSDHdsc3QtYWxzLTE4MhIMd2xzdC1ydHUtMTgyEgx3bHN0LWxkdS0xODISDHdsc3Qtc2x1LTE4MiAWKLYBMkMIwNHKmQUSDHdsc3QtYWxzLTE5MBIMd2xzdC1ydHUtMTkwEgx3bHN0LWxkdS0xOTASDHdsc3Qtc2x1LTE5MCAWKL4BMkIIwNHKmQUSDHdsc3QtbGR1LTEyMBIMd2xzdC1zbHUtMTIwEgx3bHN0LWFscy0xMjASDHdsc3QtcnR1LTEyMCAWKHgyQwjA0cqZBRIMd2xzdC1sZHUtMTQyEgx3bHN0LXNsdS0xNDISDHdsc3QtYWxzLTE0MhIMd2xzdC1ydHUtMTQyIBYojgEyQwjA0cqZBRIMd2xzdC1sZHUtMTQ1Egx3bHN0LXNsdS0xNDUSDHdsc3QtYWxzLTE0NRIMd2xzdC1ydHUtMTQ1IBYokQEyQwjA0cqZBRIMd2xzdC1zbHUtMTQ3Egx3bHN0LWFscy0xNDcSDHdsc3QtcnR1LTE0NxIMd2xzdC1sZHUtMTQ3IBYokwEyQwjA0cqZBRIMd2xzdC1zbHUtMTc3Egx3bHN0LWFscy0xNzcSDHdsc3QtcnR1LTE3NxIMd2xzdC1sZHUtMTc3IBYosQEyHAjd5f7LBxINd2xzdC1ydHUtNTExMxgEIBwo+ScyQwjA0cqZBRIMd2xzdC1sZHUtMTQxEgx3bHN0LXNsdS0xNDESDHdsc3QtYWxzLTE0MRIMd2xzdC1ydHUtMTQxIBYojQEyQwjA0cqZBRIMd2xzdC1hbHMtMTU3Egx3bHN0LXJ0dS0xNTcSDHdsc3QtbGR1LTE1NxIMd2xzdC1zbHUtMTU3IBYonQEyQwjA0cqZBRIMd2xzdC1hbHMtMTc2Egx3bHN0LXJ0dS0xNzYSDHdsc3QtbGR1LTE3NhIMd2xzdC1zbHUtMTc2IBYosAEyQgjA0cqZBRIMd2xzdC1sZHUtMTIzEgx3bHN0LXNsdS0xMjMSDHdsc3QtYWxzLTEyMxIMd2xzdC1ydHUtMTIzIBYoezJDCMDRypkFEgx3bHN0LWxkdS0xNDMSDHdsc3Qtc2x1LTE0MxIMd2xzdC1hbHMtMTQzEgx3bHN0LXJ0dS0xNDMgFiiPATIiCPWIgrYBEgp3bHN0LXNsdS0zEgp3bHN0LXJ0dS0zIBAoAzIgCN3l9pMBEgp3bHN0LWFscy0zEgp3bHN0LWFscy0xKAMyQgjA0cqZBRIMd2xzdC1ydHUtMTEwEgx3bHN0LWxkdS0xMTASDHdsc3Qtc2x1LTExMBIMd2xzdC1hbHMtMTEwIBYobjJDCMDRypkFEgx3bHN0LWxkdS0xMjgSDHdsc3Qtc2x1LTEyOBIMd2xzdC1hbHMtMTI4Egx3bHN0LXJ0dS0xMjggFiiAATJDCMDRypkFEgx3bHN0LWFscy0xNjcSDHdsc3QtcnR1LTE2NxIMd2xzdC1sZHUtMTY3Egx3bHN0LXNsdS0xNjcgFiinATJCCMDRypkFEgx3bHN0LXJ0dS0xMjYSDHdsc3QtbGR1LTEyNhIMd2xzdC1zbHUtMTI2Egx3bHN0LWFscy0xMjYgFih+MkMIwNHKmQUSDHdsc3QtcnR1LTE1ORIMd2xzdC1sZHUtMTU5Egx3bHN0LXNsdS0xNTkSDHdsc3QtYWxzLTE1OSAWKJ8BMkMIwNHKmQUSDHdsc3QtbGR1LTE2NRIMd2xzdC1zbHUtMTY1Egx3bHN0LWFscy0xNjUSDHdsc3QtcnR1LTE2NSAWKKUBMkMIwNHKmQUSDHdsc3QtbGR1LTE4ORIMd2xzdC1zbHUtMTg5Egx3bHN0LWFscy0xODkSDHdsc3QtcnR1LTE4OSAWKL0BMkMIwNHKmQUSDHdsc3QtbGR1LTE3MBIMd2xzdC1zbHUtMTcwEgx3bHN0LWFscy0xNzASDHdsc3QtcnR1LTE3MCAWKKoBMkMIwNHKmQUSDHdsc3Qtc2x1LTE3ORIMd2xzdC1hbHMtMTc5Egx3bHN0LXJ0dS0xNzkSDHdsc3QtbGR1LTE3OSAWKLMBMkMIwNHKmQUSDHdsc3Qtc2x1LTE5MRIMd2xzdC1hbHMtMTkxEgx3bHN0LXJ0dS0xOTESDHdsc3QtbGR1LTE5MSAWKL8BMkMIwNHKmQUSDHdsc3QtbGR1LTE5MxIMd2xzdC1zbHUtMTkzEgx3bHN0LWFscy0xOTMSDHdsc3QtcnR1LTE5MyAWKMEBMkIIwNHKmQUSDHdsc3QtcnR1LTEwNhIMd2xzdC1sZHUtMTA2Egx3bHN0LXNsdS0xMDYSDHdsc3QtYWxzLTEwNiAWKGoyQgjA0cqZBRIMd2xzdC1sZHUtMTExEgx3bHN0LXNsdS0xMTESDHdsc3QtYWxzLTExMRIMd2xzdC1ydHUtMTExIBYobzJDCMDRypkFEgx3bHN0LXJ0dS0xNDASDHdsc3QtbGR1LTE0MBIMd2xzdC1zbHUtMTQwEgx3bHN0LWFscy0xNDAgFiiMATJDCMDRypkFEgx3bHN0LXNsdS0xNjISDHdsc3QtYWxzLTE2MhIMd2xzdC1ydHUtMTYyEgx3bHN0LWxkdS0xNjIgFiiiATJCCMDRypkFEgx3bHN0LXNsdS0xMTQSDHdsc3QtYWxzLTExNBIMd2xzdC1ydHUtMTE0Egx3bHN0LWxkdS0xMTQgFihyMkIIwNHKmQUSDHdsc3QtbGR1LTExNhIMd2xzdC1zbHUtMTE2Egx3bHN0LWFscy0xMTYSDHdsc3QtcnR1LTExNiAWKHQyQgjA0cqZBRIMd2xzdC1sZHUtMTE5Egx3bHN0LXNsdS0xMTkSDHdsc3QtYWxzLTExORIMd2xzdC1ydHUtMTE5IBYodzJDCMDRypkFEgx3bHN0LWxkdS0xNDYSDHdsc3Qtc2x1LTE0NhIMd2xzdC1hbHMtMTQ2Egx3bHN0LXJ0dS0xNDYgFiiSATJDCMDRypkFEgx3bHN0LWxkdS0xOTgSDHdsc3Qtc2x1LTE5OBIMd2xzdC1hbHMtMTk4Egx3bHN0LXJ0dS0xOTggFijGATJCCMDRypkFEgx3bHN0LWFscy0xMDcSDHdsc3QtcnR1LTEwNxIMd2xzdC1sZHUtMTA3Egx3bHN0LXNsdS0xMDcgFihrMkMIwNHKmQUSDHdsc3QtbGR1LTE1NhIMd2xzdC1zbHUtMTU2Egx3bHN0LWFscy0xNTYSDHdsc3QtcnR1LTE1NiAWKJwBMkMIwNHKmQUSDHdsc3Qtc2x1LTE3MRIMd2xzdC1hbHMtMTcxEgx3bHN0LXJ0dS0xNzESDHdsc3QtbGR1LTE3MSAWKKsBMkMIwNHKmQUSDHdsc3QtcnR1LTE3NBIMd2xzdC1sZHUtMTc0Egx3bHN0LXNsdS0xNzQSDHdsc3QtYWxzLTE3NCAWKK4BMkMIwNHKmQUSDHdsc3QtbGR1LTE1OBIMd2xzdC1zbHUtMTU4Egx3bHN0LWFscy0xNTgSDHdsc3QtcnR1LTE1OCAWKJ4BMkMIwNHKmQUSDHdsc3QtbGR1LTE2MxIMd2xzdC1zbHUtMTYzEgx3bHN0LWFscy0xNjMSDHdsc3QtcnR1LTE2MyAWKKMBMkMIwNHKmQUSDHdsc3QtbGR1LTE5MhIMd2xzdC1zbHUtMTkyEgx3bHN0LWFscy0xOTISDHdsc3QtcnR1LTE5MiAWKMAB"
	// b, _ := base64.StdEncoding.DecodeString(s)
	// msg := &msgctl.MsgWithCtrl{}
	// msg.Unmarshal(b)
	// println(fmt.Sprintf("%+v", msg.Syscmds.OnlineRtus))
	// for _, v := range msg.Syscmds.OnlineInfo {
	// 	println(fmt.Sprintf("---%d\t%+v", v.PhyId, v.Members))
	// }
	// s := `{"opt":1,"loop":[1,3],"id":[1,2,3,4,5]}`
	// b := gjson.Parse(s)
	// b.Get("loop").ForEach(func(_, value gjson.Result) bool {
	// 	println(value.Int())
	// 	return true
	// })
	// a:=gjson.Get(js, "agee")
	// println(a.Int())
	// os.Exit(0)
	// testCtldata()
	// testCtldataPb2()
	// testCtldatajson()
	//testCtldataV6()
	// testTmldata()
	// testTmldataV6()
	// testTmldataNB()
	//println(fmt.Sprintf("%+v", gopsu.Uint642Bytes(uint64(12333), false)))
	// aaa("adsfa", 12313, "asdfas", int64(1211), 1231.9876)
	// countCRC()
	// for {
	// 	time.Sleep(time.Second)
	// }
	os.Exit(0)

}
