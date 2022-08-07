package persistence

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
)

const initCounter = int64(-1)

var (
	ErrNotFound = errors.New("not found")
)

type DeviceSignatureRepository interface {
	SaveDevice(device *domain.DeviceKeyPairRaw) (uuid.UUID, error)
	GetDevice(deviceID uuid.UUID) (domain.DeviceKeyPairRaw, error)
	GetAndSaveSignature(deviceID uuid.UUID, data []byte) (signature []byte, count int64, err error)
	GetSignatureAndCount(deviceID uuid.UUID) (signature []byte, count int64, err error)
}

type deviceKey struct {
	domain.Device
	pubKey     []byte
	privateKey []byte
}

type InMemoryRepository struct {
	devices   map[uuid.UUID]deviceKey
	counter   map[uuid.UUID]int64
	signature map[uuid.UUID][]byte

	rw *sync.RWMutex
}

func NewInMemoryRepository(rw *sync.RWMutex) *InMemoryRepository {
	return &InMemoryRepository{
		rw:        rw,
		devices:   make(map[uuid.UUID]deviceKey),
		counter:   make(map[uuid.UUID]int64),
		signature: make(map[uuid.UUID][]byte),
	}
}

func (i *InMemoryRepository) SaveDevice(device *domain.DeviceKeyPairRaw) (uuid.UUID, error) {
	if i.rw.TryLock() {
		i.rw.Lock()
		defer i.rw.Unlock()
	}

	i.devices[device.ID] = deviceKey{
		Device:     device.Device,
		pubKey:     device.PublicKey,
		privateKey: device.PrivateKey,
	}

	i.counter[device.ID] = initCounter

	return device.ID, nil
}

func (i *InMemoryRepository) GetDevice(deviceID uuid.UUID) (domain.DeviceKeyPairRaw, error) {
	if i.rw.TryRLock() {
		i.rw.RLock()
		defer i.rw.RUnlock()
	}

	if device, ok := i.devices[deviceID]; ok {
		return domain.DeviceKeyPairRaw{
			Device: domain.Device{
				ID:        deviceID,
				Algorithm: device.Algorithm,
				Label:     device.Label,
			},
			PublicKey:  device.pubKey,
			PrivateKey: device.privateKey,
		}, nil
	}

	return domain.DeviceKeyPairRaw{}, ErrNotFound
}

func (i *InMemoryRepository) GetAndSaveSignature(deviceID uuid.UUID, data []byte) (signature []byte, count int64, err error) {
	if i.rw.TryLock() {
		i.rw.Lock()
		defer i.rw.Unlock()
	}

	signature, count, errGet := i.GetSignatureAndCount(deviceID)
	if errors.Is(errGet, ErrNotFound) {
		signature = data
	}

	i.signature[deviceID] = data

	atomic.AddInt64(&count, 1)
	i.counter[deviceID] = count

	return
}

func (i *InMemoryRepository) GetSignatureAndCount(deviceID uuid.UUID) (signature []byte, count int64, err error) {
	if i.rw.TryRLock() {
		i.rw.RLock()
		defer i.rw.RUnlock()
	}

	if signature, ok := i.signature[deviceID]; ok {
		return signature, i.counter[deviceID], nil
	}

	return nil, initCounter, ErrNotFound
}
