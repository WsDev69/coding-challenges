package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var (
	ErrWrongKeyPairType    = errors.New("keyPair isn't")
	ErrWrongKeyPairTypeRSA = errors.New("keyPair isn't")
	ErrWrongKeyPairTypeECC = fmt.Errorf("ECC %f", ErrWrongKeyPairType)
)

// ECCKeyPair is a DTO that holds ECC private and public keys.
type ECCKeyPair struct {
	Public  *ecdsa.PublicKey
	Private *ecdsa.PrivateKey
}

// ECCMarshaler can encode and decode an ECC key pair.
type ECCMarshaler struct{}

// NewECCMarshaller creates a new ECCMarshaler.
func NewECCMarshaller() KeyPairMarshaller {
	return &ECCMarshaler{}
}

// Marshal takes an ECCKeyPair and encodes it to be written on disk.
// It returns the public and the private key as a byte slice.
func (m ECCMarshaler) Marshal(keyPair interface{}) (public, private []byte, err error) {
	v, ok := keyPair.(*ECCKeyPair)
	if !ok {
		err = ErrWrongKeyPairTypeECC

		return
	}
	privateKeyBytes, err := x509.MarshalECPrivateKey(v.Private)
	if err != nil {
		return
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(v.Public)
	if err != nil {
		return
	}

	private = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE_KEY",
		Bytes: privateKeyBytes,
	})

	public = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC_KEY",
		Bytes: publicKeyBytes,
	})

	return
}

// UnMarshal assembles an ECCKeyPair from an encoded private key.
func (m ECCMarshaler) UnMarshal(privateKeyBytes []byte) (keyPair interface{}, err error) {
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &ECCKeyPair{
		Private: privateKey,
		Public:  &privateKey.PublicKey,
	}, nil
}
