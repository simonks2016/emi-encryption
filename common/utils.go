package common

import "github.com/simonks2016/emi-encryption/types"

func ToBytes[T types.StringOrBytes](data T) []byte {
	switch v := any(data).(type) {
	case string:
		return []byte(v)
	case []byte:
		return v
	default:
		return nil
	}
}
