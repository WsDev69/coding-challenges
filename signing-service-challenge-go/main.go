package main

import (
	"errors"
	"log"
	"sync"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/service"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/api"
)

const (
	ListenAddress = ":8080"
)

var ErrWrongType = errors.New("wrong type cast")

func main() {
	factory := service.NewAlgorithmFactoryV0()
	factory.Add(domain.RSA, func(algorithm domain.Algorithm, privateKey []byte) (crypto.Signer, error) {
		m := crypto.NewRSAMarshaller()
		keyPairRaw, err := m.UnMarshal(privateKey)
		if err != nil {
			return nil, err
		}

		keyPair, ok := keyPairRaw.(*crypto.RSAKeyPair)
		if !ok {
			return nil, ErrWrongType
		}

		return crypto.NewRSASigner(keyPair, crypto.Config{}), nil
	})

	factory.Add(domain.ECDSA, func(algorithm domain.Algorithm, privateKey []byte) (crypto.Signer, error) {
		m := crypto.NewECCMarshaller()
		keyPairRaw, err := m.UnMarshal(privateKey)
		if err != nil {
			return nil, err
		}

		keyPair, ok := keyPairRaw.(*crypto.ECCKeyPair)
		if !ok {
			return nil, ErrWrongType
		}
		return crypto.NewECCSigner(keyPair, crypto.Config{}), nil
	})
	repo := persistence.NewInMemoryRepository(&sync.RWMutex{})
	signature := service.NewV0Signature(repo, factory)

	server := api.NewServer(ListenAddress, signature)

	if err := server.Run(); err != nil {
		log.Fatal("Could not start server on ", ListenAddress)
	}
}
