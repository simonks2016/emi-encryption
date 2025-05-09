package types

type Alg[T StringOrBytes] func(T, T) string
