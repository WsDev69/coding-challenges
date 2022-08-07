package service

import (
	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
)

type FnAlgorithm = func(algorithm domain.Algorithm, privateKey []byte) (crypto.Signer, error)

type AlgorithmFactory interface {
	Add(algorithm domain.Algorithm, fn FnAlgorithm)
	Get(algorithm domain.Algorithm, privateKey []byte) (crypto.Signer, error)
}

type AlgorithmFactoryV0 struct {
	process map[domain.Algorithm]FnAlgorithm
}

func NewAlgorithmFactoryV0() AlgorithmFactory {
	return &AlgorithmFactoryV0{
		process: make(map[domain.Algorithm]FnAlgorithm),
	}
}

func (a AlgorithmFactoryV0) Add(algorithm domain.Algorithm, fn FnAlgorithm) {
	a.process[algorithm] = fn
}

func (a AlgorithmFactoryV0) Get(algorithm domain.Algorithm, privateKey []byte) (crypto.Signer, error) {
	return a.process[algorithm](algorithm, privateKey)
}
