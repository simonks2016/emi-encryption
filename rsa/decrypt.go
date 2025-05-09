package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/simonks2016/emi-encryption/common"
	errors2 "github.com/simonks2016/emi-encryption/errors"
	"github.com/simonks2016/emi-encryption/types"
)

// RSAPrivateDecrypt 用私钥解密
func PrivateDecrypt[T types.StringOrBytes](CipherText T, privateKey T) ([]byte, error) {

	cipherText := common.ToBytes[T](CipherText)
	privatePEM := common.ToBytes[T](privateKey)

	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return nil, errors2.ErrFailedToParsePEMBlock.Error()
	}

	var privKey *rsa.PrivateKey
	var err error

	switch block.Type {
	case "PRIVATE KEY":
		// 尝试解析 PKCS#8 格式
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS#8 parse error: %w", err)
		}
		var ok bool
		privKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors2.ErrNoRSaPrivateKey.Error()
		}

	case "RSA PRIVATE KEY":
		// 解析 PKCS#1 格式
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS#1 parse error: %w", err)
		}

	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	// 解密
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, cipherText)
	if err != nil {
		return nil, fmt.Errorf("RSA decrypt error: %w", err)
	}

	return plainText, nil
}
