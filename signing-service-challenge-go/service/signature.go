package service

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/google/uuid"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
)

var (
	emptySigned = domain.SignedTransaction{}
)

type Signature interface {
	CreateDevice(ctx context.Context, device domain.Device) (uuid.UUID, error)
	SignTx(ctx context.Context, deviceID uuid.UUID, data string) (domain.SignedTransaction, error)
}

type V0Signature struct {
	repo persistence.DeviceSignatureRepository

	factory AlgorithmFactory
}

func NewV0Signature(repo persistence.DeviceSignatureRepository, factory AlgorithmFactory) Signature {
	return &V0Signature{repo: repo, factory: factory}
}

func (v V0Signature) CreateDevice(_ context.Context, device domain.Device) (uuid.UUID, error) {
	_, err := v.repo.GetDevice(device.ID)

	if !errors.Is(err, persistence.ErrNotFound) {
		return uuid.Nil, domain.ErrDeviceAlreadyExist
	}

	pub, private, err := crypto.GetKeyPair(device.Algorithm)
	if err != nil {
		return uuid.Nil, err
	}

	deviceRaw := domain.DeviceKeyPairRaw{
		Device:     device,
		PublicKey:  pub,
		PrivateKey: private,
	}

	return v.repo.SaveDevice(&deviceRaw)
}

func (v V0Signature) SignTx(_ context.Context, deviceID uuid.UUID, data string) (domain.SignedTransaction, error) {
	d, err := v.repo.GetDevice(deviceID)
	if err != nil {
		if errors.Is(err, persistence.ErrNotFound) {
			return emptySigned, domain.ErrDeviceNotFound
		}
		return emptySigned, err
	}

	signer, err := v.factory.Get(d.Algorithm, d.PrivateKey)
	if err != nil {
		return emptySigned, err
	}

	signed, err := signer.Sign([]byte(data))
	if err != nil {
		return emptySigned, err
	}

	prev, counter, err := v.repo.GetAndSaveSignature(deviceID, signed)
	if err != nil {
		return emptySigned, err
	}

	return domain.SignedTransaction{
		Signature:     base64.StdEncoding.EncodeToString(signed),
		Counter:       counter,
		RawData:       data,
		LastSignature: base64.StdEncoding.EncodeToString(prev),
	}, nil
}
