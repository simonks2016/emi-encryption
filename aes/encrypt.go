package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/simonks2016/emi-encryption/common"
	"github.com/simonks2016/emi-encryption/padding"
	"github.com/simonks2016/emi-encryption/types"
)

// AES 加密函数（CBC + PKCS7 + base64 输出）
func Encrypt[T types.StringOrBytes](data T, key T, isNeedBase64Encode bool) (string, error) {
	dataBytes := common.ToBytes[T](data)
	keyBytes := common.ToBytes[T](key)

	// 填充 key 到 32 字节（AES-256）
	if len(keyBytes) < 32 {
		paddingBytes := make([]byte, 32-len(keyBytes))
		keyBytes = append(keyBytes, paddingBytes...)
	} else if len(keyBytes) > 32 {
		keyBytes = keyBytes[:32]
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	dataBytes = padding.Pkcs7Padding(dataBytes, blockSize)

	iv := keyBytes[:blockSize] // 可以替换为随机 iv 以提升安全性
	mode := cipher.NewCBCEncrypter(block, iv)

	encrypted := make([]byte, len(dataBytes))
	mode.CryptBlocks(encrypted, dataBytes)

	if isNeedBase64Encode {
		return base64.StdEncoding.EncodeToString(encrypted), nil
	}
	return fmt.Sprintf("%x", encrypted), nil
}

func smartDecode(s string) ([]byte, error) {
	isHex := true
	for _, r := range s {
		if !(('0' <= r && r <= '9') || ('a' <= r && r <= 'f') || ('A' <= r && r <= 'F')) {
			isHex = false
			break
		}
	}

	if isHex {
		return hex.DecodeString(s)
	}
	return base64.StdEncoding.DecodeString(s)
}
