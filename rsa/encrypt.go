package rsa

import (
	"Emi-Encryption/common"
	errors2 "Emi-Encryption/errors"
	"Emi-Encryption/types"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func PublicKeyEncrypt[T types.StringOrBytes](text T, publicKey T) ([]byte, error) {

	plainText := common.ToBytes[T](text)
	pubPEM := common.ToBytes[T](publicKey)

	block, _ := pem.Decode(pubPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors2.ErrInvalidPublicKey.Error()
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pubKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors2.ErrNoRSAPublicKey.Error()
	}

	return rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)
}
