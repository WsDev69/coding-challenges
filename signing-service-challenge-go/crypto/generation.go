package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
)

const bits = 4096

var (
	eccGenerator = &ECCGenerator{}
	rsaGenerator = &RSAGenerator{}
)

var (
	ErrWrongAlgorithmType = errors.New("wrong type of Algorithm")
)

type KeyPair interface {
	Generate() (KeyPairMarshaller, error)
}

// RSAGenerator generates a RSA key pair.
type RSAGenerator struct{}

// Generate generates a new RSAKeyPair.
func (g *RSAGenerator) Generate() (*RSAKeyPair, error) {
	// Security has been ignored for the sake of simplicity.
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	return &RSAKeyPair{
		Public:  &key.PublicKey,
		Private: key,
	}, nil
}

// ECCGenerator generates an ECC key pair.
type ECCGenerator struct{}

// Generate generates a new ECCKeyPair.
func (g *ECCGenerator) Generate() (*ECCKeyPair, error) {
	// Security has been ignored for the sake of simplicity.
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECCKeyPair{
		Public:  &key.PublicKey,
		Private: key,
	}, nil
}

func GetKeyPair(algorithm domain.Algorithm) (public, private []byte, err error) {
	switch algorithm {
	case domain.RSA:
		k, errGenerator := rsaGenerator.Generate()
		if errGenerator != nil {
			err = errGenerator

			return
		}

		marshaller := NewRSAMarshaller()
		return marshaller.Marshal(k)
	case domain.ECDSA:
		k, errGenerator := eccGenerator.Generate()
		if errGenerator != nil {
			err = errGenerator

			return
		}

		marshaller := NewECCMarshaller()
		return marshaller.Marshal(k)
	default:
		err = ErrWrongAlgorithmType
		return
	}
}
