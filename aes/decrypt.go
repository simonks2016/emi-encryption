package aes

import (
	"Emi-Encryption/common"
	"Emi-Encryption/padding"
	"Emi-Encryption/types"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func Decrypt[T types.StringOrBytes](cipherText T, key T) (string, error) {
	keyBytes := common.ToBytes[T](key)

	// 填充或截断 key 到 32 字节
	if len(keyBytes) < 32 {
		paddingBytes := make([]byte, 32-len(keyBytes))
		keyBytes = append(keyBytes, paddingBytes...)
	} else if len(keyBytes) > 32 {
		keyBytes = keyBytes[:32]
	}

	// 解码 cipherText（支持 hex / base64）
	cipherStr := string(common.ToBytes(cipherText))
	cipherBytes, err := smartDecode(cipherStr)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	if len(cipherBytes)%blockSize != 0 {
		return "", fmt.Errorf("cipherBytes is not a multiple of block size")
	}

	iv := keyBytes[:blockSize]
	mode := cipher.NewCBCDecrypter(block, iv)

	plain := make([]byte, len(cipherBytes))
	mode.CryptBlocks(plain, cipherBytes)

	plain, err = padding.Pkcs7UnPadding(plain)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}
