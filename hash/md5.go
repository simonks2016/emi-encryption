package hash

import (
	"crypto/md5"
	"fmt"
	"github.com/simonks2016/emi-encryption/common"
	"github.com/simonks2016/emi-encryption/types"
)

func M5[T types.StringOrBytes](str T) string {
	var data = common.ToBytes[T](str)
	//md5 加密
	hash := md5.Sum(data)
	return fmt.Sprintf("%x", hash)
}
