# 🔐 Emi-Encryption - 加密模块

`EMI-Encryption` 提供了统一泛型封装的 AES、RSA 加解密与签名功能，适用于多种字符串或字节数组格式。

---

## ✨ 特性

- ✅ 支持 AES 对称加密（支持字符串或字节）
- ✅ 支持 RSA 非对称加密（PKCS#1 / PKCS#8）
- ✅ 支持结构签名生成（适配不同算法，如 HS256 等）
- ✅ 使用 Go 泛型增强类型兼容性

---

## 📦 安装

```bash
go get github.com/simonks2016/emi-encryption
```

## AES加密函数
```go
cipherText, err := EncryptAES("Hello World", "your-32-byte-key")

// 解密
plainText, err := DecryptAES(cipherText, "your-32-byte-key")
```
## 签名函数
```go
// dataModel 是任意结构体类型，map[string]any,string,float,int等
sig := Signature(dataModel, "my-secret", HS256)
// 有两个加密函数类型，分别是
func HS256[T types.StringOrBytes](data T, key T) string
func HS384[T types.StringOrBytes](data T, key T) string
```

## RSA加密函数
```go
// 加密（使用公钥 PEM）
encrypted, err := EncryptRSA([]byte("Secret Data"), publicKeyPEM)

// 解密（支持 PKCS#1 和 PKCS#8）
decrypted, err := DecryptRSA(encrypted, privateKeyPEM)
```

## 📚类型接口

```go
package types

type StringOrBytes interface {
	~string | ~[]byte
}
```

## 📝License
- MIT License © 2025 pacontv.com
