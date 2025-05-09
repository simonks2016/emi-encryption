package padding

import "github.com/simonks2016/emi-encryption/errors"

// PKCS7 去填充
func Pkcs7UnPadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.ErrPadding.Error()
	}
	paddingLen := int(data[len(data)-1])
	if paddingLen > len(data) || paddingLen == 0 {
		return nil, errors.ErrPadding.Error()
	}
	for _, v := range data[len(data)-paddingLen:] {
		if int(v) != paddingLen {
			return nil, errors.ErrPadding.Error()
		}
	}
	return data[:len(data)-paddingLen], nil
}
