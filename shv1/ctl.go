package shv1

import (
	"fmt"

	"github.com/pkg/errors"
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

	return lstf
}
