package hash

import (
	"Emi-Encryption/common"
	"Emi-Encryption/types"
	"crypto/md5"
	"fmt"
)

func M5[T types.StringOrBytes](str T) string {
	var data = common.ToBytes[T](str)
	//md5 加密
	hash := md5.Sum(data)
	return fmt.Sprintf("%x", hash)
}
