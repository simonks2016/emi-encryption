package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/simonks2016/emi-encryption/common"
	"github.com/simonks2016/emi-encryption/types"
)

func HS256[T types.StringOrBytes](data T, key T) string {
	var d = common.ToBytes[T](data)
	var k = common.ToBytes[T](key)

	h := hmac.New(sha256.New, k)
	h.Write(d)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func HS384[T types.StringOrBytes](data T, key T) string {
	var d = common.ToBytes[T](data)
	var k = common.ToBytes[T](key)
	h := hmac.New(sha512.New384, k)
	h.Write(d)
	return fmt.Sprintf("%x", h.Sum(nil))
}
