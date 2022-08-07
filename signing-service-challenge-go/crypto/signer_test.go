package crypto_test

import (
	"errors"
	"testing"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
)

func TestNewRSASigner(t *testing.T) {
	t.Parallel()

	signer, err := getSigner()
	if err != nil {
		t.Fatal(err)
	}

	if signer == nil {
		t.Fatal(errors.New("signer instance is nil"))
	}
}

func TestRSASigner_Sign(t *testing.T) {
	t.Parallel()

	signer, err := getSigner()
	if err != nil {
		t.Fatal(err)
	}

	src := []byte("My name is Ihor. I'm working on the tech task. My name is Ihor. I'm working on the tech task. . . .")
	data, err := signer.Sign(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal(errors.New("wrong result"))
	}
}

func getSigner() (crypto.Signer, error) {
	generator := crypto.RSAGenerator{}
	keyPair, err := generator.Generate()
	if err != nil {
		return nil, err
	}
	return crypto.NewRSASigner(keyPair, crypto.Config{}), nil
}
