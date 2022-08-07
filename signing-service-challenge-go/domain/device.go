package domain

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

type Algorithm int

const (
	RSA   Algorithm = iota
	ECDSA Algorithm = iota
)

var (
	ErrNotFound           = errors.New("not found")
	ErrDeviceNotFound     = fmt.Errorf("device %f", ErrNotFound)
	ErrDeviceAlreadyExist = fmt.Errorf("device already exist")
)

type Device struct {
	ID        uuid.UUID `json:"id"`
	Algorithm Algorithm `json:"algorithm"`
	Label     *string   `json:"label"`
}

type DeviceKeyPairRaw struct {
	Device
	PublicKey  []byte `json:"pub_key"`
	PrivateKey []byte `json:"private_key"`
}

type SignedTransaction struct {
	Signature     string `json:"signature"`
	Counter       int64  `json:"counter"`
	RawData       string `json:"raw_data"`
	LastSignature string `json:"last_signature"`
}
