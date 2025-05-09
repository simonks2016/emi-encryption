package common

import "Emi-Encryption/types"

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
