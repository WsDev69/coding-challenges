package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"hash"
	"io"
)

// Signer defines a contract for different types of signing implementations.
type Signer interface {
	Sign(dataToBeSigned []byte) ([]byte, error)
}

type RSASigner struct {
	keyPair *RSAKeyPair

	reader io.Reader
	hash   hash.Hash
}

type ECCSigner struct {
	keyPair *ECCKeyPair

	reader io.Reader
	hash   hash.Hash
}

type Config struct {
	reader io.Reader
}

// NewRSASigner returns new RSA implementation of Signer
func NewRSASigner(keyPair *RSAKeyPair, config Config) Signer {
	signer := &RSASigner{keyPair: keyPair}
	if config.reader == nil {
		signer.reader = rand.Reader
		signer.hash = sha256.New()

		return signer
	}

	signer.reader = config.reader
	return signer
}

// NewECCSigner returns new ecdsa implementation of Signer
func NewECCSigner(keyPair *ECCKeyPair, config Config) Signer {
	signer := &ECCSigner{keyPair: keyPair}
	if config.reader == nil {
		signer.reader = rand.Reader
		signer.hash = sha256.New()

		return signer
	}

	signer.reader = config.reader
	return signer
}

func (r *RSASigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	res, err := rsa.EncryptPKCS1v15(r.reader, r.keyPair.Public, dataToBeSigned)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (signer *ECCSigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, signer.keyPair.Private, dataToBeSigned)
	if err != nil {
		return nil, err
	}

	// print the signature
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)

	return signature, nil
}
