package Emi_Encryption

import (
	"github.com/simonks2016/emi-encryption/aes"
	"github.com/simonks2016/emi-encryption/requestId"
	"github.com/simonks2016/emi-encryption/rsa"
	"github.com/simonks2016/emi-encryption/types"
)

func EncryptAES[T types.StringOrBytes](data, key T) (string, error) {
	return aes.Encrypt[T](data, key, false)
}
func DecryptAES[T types.StringOrBytes](cipherText, key T) (string, error) {
	return aes.Decrypt[T](cipherText, key)
}
func Signature(dataModel any, secret string, alg types.Alg[string]) string {
	modelSign := requestId.DataModelGenSignature(dataModel)
	// 返回密文
	return alg(modelSign, secret)
}
func EncryptRSA[T types.StringOrBytes](data, key T) ([]byte, error) {
	return rsa.PublicKeyEncrypt[T](data, key)
}
func DecryptRSA[T types.StringOrBytes](cipherText, key T) ([]byte, error) {
	return rsa.PrivateDecrypt[T](cipherText, key)
}
