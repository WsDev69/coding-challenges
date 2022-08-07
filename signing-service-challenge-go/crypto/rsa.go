package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// RSAKeyPair is a DTO that holds RSA private and public keys.
type RSAKeyPair struct {
	Public  *rsa.PublicKey
	Private *rsa.PrivateKey
}

// RSAMarshaler can encode and decode an RSA key pair.
type RSAMarshaler struct{}

func (m *RSAMarshaler) Marshal(keyPair interface{}) (public, private []byte, err error) {
	v, ok := keyPair.(*RSAKeyPair)
	if !ok {
		err = ErrWrongKeyPairTypeRSA

		return
	}
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(v.Private)
	publicKeyBytes := x509.MarshalPKCS1PublicKey(v.Public)

	private = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA_PRIVATE_KEY",
		Bytes: privateKeyBytes,
	})

	public = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA_PUBLIC_KEY",
		Bytes: publicKeyBytes,
	})

	return
}

func (m *RSAMarshaler) UnMarshal(privateKeyBytes []byte) (keyPair interface{}, err error) {
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &RSAKeyPair{
		Private: privateKey,
		Public:  &privateKey.PublicKey,
	}, nil
}

// NewRSAMarshaller creates a new RSAMarshaler.
func NewRSAMarshaller() KeyPairMarshaller {
	return &RSAMarshaler{}
}
