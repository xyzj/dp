package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	// "github.com/tidwall/gjson"

	// "math"
	// "strconv"
	// "time"

	dpv5 "./v5local"
	v6 "./v6"
	jsoniter "github.com/json-iterator/go"
	"github.com/xyzj/gopsu"
	msgctl "gitlab.local/proto/msgjk"
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
	s = strings.Split("68 0E 00 0E 00 68 0B 01 01 12 04 00 00 00 60 00 00 01 00 02 86 16", " ")
	s = gopsu.SplitStringWithLen("68112233445566689C437D3F0100B700383635383233303430393734373833343630303437343938393032323433383938363034353431313139393134323232343308EB0300000C0000008E4FA816", 2)
	//s = strings.Split("68-11-00-11-00-68-eb-01-01-12-01-00-00-0c-70-00-00-20-00-ff-ff-90-ff-29-16-68-17-00-17-00-68-eb-01-01-12-01-00-00-0c-70-00-00-01-01-00-00-00-00-00-00-00-00-90-ff-0d-16-68-19-00-19-00-68-eb-01-01-12-01-00-00-0c-70-00-00-02-02-ee-ee-00-00-00-00-00-00-00-00-90-ff-eb-16-68-c9-00-c9-00-68-eb-01-01-12-01-00-00-0c-70-ff-ff-01-00-27-11-06-09-13-0c-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-90-ff-c0-16-68-50-00-50-00-68-eb-01-01-12-01-00-00-0c-70-00-00-04-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-90-ff-0f-16", "-")
	s = strings.Split("68-01-00-00-00-00-00-68-9c-43-7d-3f-01-00-b7-00-38-36-37-37-32-36-30-33-31-39-30-31-31-36-30-34-36-30-31-31-33-30-34-36-30-36-32-37-32-32-38-39-38-36-31-31-31-39-32-36-34-30-30-36-30-34-30-30-33-33-35-91-02-00-80-b5-00-00-00-3e-b9-24-16", "-")
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
	a := int64(0)
	b := true
	c := 0
	// t := false
	r := dpv5.ClassifyTmlData(ss, &a, &c, &c, &b, 193)
	//r := v6.ClassifyTmlData(ss, 0, 0)
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
	s = gopsu.SplitStringWithLen("68112233445566689C437D3F0100B700383635383233303430393734373833343630303437343938393032323433383938363034353431313139393134323232343308EB0300000C0000008E4FA816", 2)
	//s = strings.Split("68-11-00-11-00-68-eb-01-01-12-01-00-00-0c-70-00-00-20-00-ff-ff-90-ff-29-16-68-17-00-17-00-68-eb-01-01-12-01-00-00-0c-70-00-00-01-01-00-00-00-00-00-00-00-00-90-ff-0d-16-68-19-00-19-00-68-eb-01-01-12-01-00-00-0c-70-00-00-02-02-ee-ee-00-00-00-00-00-00-00-00-90-ff-eb-16-68-c9-00-c9-00-68-eb-01-01-12-01-00-00-0c-70-ff-ff-01-00-27-11-06-09-13-0c-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-ee-90-ff-c0-16-68-50-00-50-00-68-eb-01-01-12-01-00-00-0c-70-00-00-04-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-90-ff-0f-16", "-")
	s = strings.Split("68-01-00-00-00-00-00-68-9c-43-7d-3f-01-00-b7-00-38-36-37-37-32-36-30-33-31-39-30-31-31-36-30-34-36-30-31-31-33-30-34-36-30-36-32-37-32-32-38-39-38-36-31-31-31-39-32-36-34-30-30-36-30-34-30-30-33-33-35-91-02-00-80-b5-00-00-00-3e-b9-24-16", "-")
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
	r := v6.ClassifyTmlData(ss, 0, 0)
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
	s = `{"mod":2,"src":2,"ver":1,"tra":1,"tver":1,"cmd":"wlst.rtu.4101","gid":0,"rcv":0,"ret":0},"args":{"port":10606,"addr":[826],"cid":0,"scid":0},"data":{"ln":12,"vr":300,"l1":100,"l2":100,"l3":100,"l4":100,"l5":100,"l6":100,"l7":100,"l8":100,"l9":100,"l10":100,"l11":100,"l12":100,"l13":0,"l14":0,"l15":0,"l16":0,"l17":0,"l18":0,"l19":0,"l20":0,"l21":0,"l22":0,"l23":0,"l24":0,"l25":0,"l26":0,"l27":0,"l28":0,"l29":0,"l30":0,"l31":0,"l32":0,"l33":0,"l34":0,"l35":0,"l36":0,"l37":0,"l38":0,"l39":0,"l40":0,"l41":0,"l42":0,"l43":0,"l44":0,"l45":0,"l46":0,"l47":0,"l48":0}}`
	z := dpv5.ClassifyCtlData([]byte("`"+s+"`"), &a)
	println(fmt.Sprintf("%+v", string(z.Unfinish)))
	for k, v := range z.Do {
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
func main() {
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
	// testTmldata()
	// println(fmt.Sprintf("%+v", gopsu.Uint642Bytes(uint64(12333), false)))
	// aaa("adsfa", 12313, "asdfas", int64(1211), 1231.9876)
	a := 220
	b := 300
	c := int(float32(a)/float32(b)*0x3ff0) & 0xff
	println(c)
	// countCRC()
	// for {
	// 	time.Sleep(time.Second)
	// }
	os.Exit(0)

}
