package main

import (
	"fmt"
	"os"
	"strings"

	// "github.com/tidwall/gjson"

	// "math"
	// "strconv"
	// "time"

	"github.com/xyzj/gopsu"
	msgctl "github.com/xyzj/proto/msgjk"

	"192.168.51.60/xy/dp/v5local"
	// "github.com/pkg/errors"
)

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
	s = strings.Split("7e-62-26-01-d9-02-28-23-e7-03-00-00-46-02-02-28-23-e7-03-00-00-6e-02-03-f4-01-64-00-00-00-00-00-03-f4-01-64-00-00-00-00-00-08-32-81-1d", "-")
	ss := make([]byte, len(s))
	for k, v := range s {
		ss[k] = gopsu.String2Int8(v, 16)
	}
	a := int64(0)
	b := true
	c := 0
	// t := false
	r := dpv5.ClassifyTmlData(ss, &a, &c, &c, &b, 193)
	fmt.Printf("%+v\n\n", r)
	// println(r.Ex)
	for k, v := range r.Do {
		//		println(fmt.Sprintf("--- %d: %+v", k, v))
		// println(fmt.Sprintf(" --- %d %+v \n", k, v))
		if len(v.Ex) > 0 {
			println("err-----------------------------------------------------------------", v.Ex)
		} else {
			// println(fmt.Sprintf("%d, %+v", k, v))
			z := dpv5.Pb2FromBytes(v.DataMsg)
			if z == nil {
				println(fmt.Sprintf("%d, %+v", k, v.DataMsg))
			} else {
				println(fmt.Sprintf("%d, %+v", k, z))
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
	js := `{"head":{"src":7,"ver":1,"tver":1,"tra":1,"cmd":"wlst.rtu.4b00","ret":1,"mod":2},"args":{"ip":[1782405612],"cid":1,"port":0,"addr":[143]},"data":{"k3":1,"k2":2,"k1":2,"k6":2,"k5":2,"k4":2}}`
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

func testCtldataPb2() {
	t := true
	// f := false
	dpv5.AnsJSON = t
	// dpv5.EnableCustomTimer = f
	a := 10001
	msg := &msgctl.MsgWithCtrl{
		Head: &msgctl.Head{
			Mod:  2,
			Src:  6,
			Ver:  1,
			Tver: 1,
			Ret:  1,
			Cmd:  "wlst.com.3e01",
			Tra:  1,
		},
		Args: &msgctl.Args{
			Port: 1024,
			Addr: []int64{1},
		},
		WlstTml: &msgctl.WlstTerminal{
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
	// js := dpv5.CodePb2(msg)
	js := "ChsIAhACGAEgASgBMAE6DXdsc3QucnR1LjEyMDASBhCACBoBAqIGGsIBFwoVMjAxOS0wMS0zMCAxNToyNDo0NyAz"
	js = "ChsIAhACGAEgASgBMAE6DXdsc3QuZWx1LjYyNTkSChCEnQEaAgECKAGiBiDCAQoKCDEyODlrZHNmihkLCAExmpmZmZmZ8T/aJgIIAQ=="
	r := dpv5.ClassifyCtlData([]byte(fmt.Sprintf("`%s`", js)), &a)
	println(fmt.Sprintf("%+v", r))
	for k, v := range r.Do {
		println(fmt.Sprintf("%d: %+v", k, v))
	}
}

func testCtldata() {
	t := true
	// f := false
	dpv5.AnsJSON = t
	// dpv5.EnableCustomTimer = f
	a := 10001
	var s = "`{\"head\": {\"src\": 2, \"gid\": 0, \"ver\": 1, \"tver\": 1, \"tra\": 1, \"rcv\": 0, \"cmd\": \"wlst.rtu.2000\", \"mod\": 2}, \"args\": {\"port\": 1024, \"addr\": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 550, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 565, 566, 567, 568, 569, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591, 592, 593, 59"
	s = `{"head":{"src":2,"ver":1,"tver":1,"tra":1,"cmd":"wlst.elu.6259","ret":1,"mod":2},"args":{"cid":1,"port":20100,"addr":[5]}}`
	z := dpv5.ClassifyCtlData([]byte(s), &a)
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
	testCtldataPb2()
	// testCtldatajson()
	// testTmldata()
	// countCRC()
	// for {
	// 	time.Sleep(time.Second)
	// }
	os.Exit(0)

}
