package types

type StringOrBytes interface {
	~string | ~[]byte
}
