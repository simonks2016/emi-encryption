package errors

import "errors"

type Error int

const (
	ErrInvalidCipherText Error = iota
	ErrPadding
	ErrInvalidPublicKey
	ErrNoRSAPublicKey
	ErrNoRSaPrivateKey
	ErrInvalidPrivateKey
	ErrInvalidFormatOnPrivateKey
	ErrFailedToParsePEMBlock
)

func (e Error) Error() error {

	switch e {
	case ErrInvalidCipherText:
		return errors.New(e.String())
	case ErrPadding:
		return errors.New(e.String())
	case ErrInvalidPublicKey:
		return errors.New(e.String())
	case ErrNoRSAPublicKey:
		return errors.New(e.String())
	case ErrInvalidPrivateKey:
		return errors.New(e.String())
	case ErrInvalidFormatOnPrivateKey:
		return errors.New(e.String())

	default:
		return nil
	}

}

func (e Error) String() string {

	switch e {
	case ErrInvalidCipherText:
		return "invalid ciphertext"
	case ErrPadding:
		return "invalid padding"
	case ErrInvalidPublicKey:
		return "invalid public key PEM"
	case ErrNoRSAPublicKey:
		return "not RSA public key"
	case ErrNoRSaPrivateKey:
		return "not RSA private key"
	case ErrInvalidPrivateKey:
		return "invalid private key PEM"
	case ErrInvalidFormatOnPrivateKey:
		return "invalid private key format (not PKCS#1 or PKCS#8)"
	case ErrFailedToParsePEMBlock:
		return "failed to parse PEM block"
	default:
		return ""
	}
}
