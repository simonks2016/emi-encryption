package Emi_Encryption

import (
	"Emi-Encryption/rsa"
	"fmt"
	"testing"
)

func TestRequestId(t *testing.T) {

	privateKey, publicKey, err := rsa.GenerateRSAKeyPair(256)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	d := []byte("aaa")
	encrypt, err := rsa.PublicKeyEncrypt(d, publicKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	decrypt, err := rsa.PrivateDecrypt(encrypt, privateKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(string(decrypt))

}
