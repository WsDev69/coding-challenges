package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/google/uuid"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
)

type Algorithm string

const (
	RSA Algorithm = "RSA"
	ECC Algorithm = "ECC"
)

type CreateSignatureDevice struct {
	ID        uuid.UUID `json:"id" validate:"required"`
	Algorithm Algorithm `json:"algorithm" validate:"required,oneof='RSA' 'ECC'"`
	Label     *string   `json:"label"`
}

// CreateSignatureDevice create a device with provided type of signature
func (s *Server) CreateSignatureDevice(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		WriteMethodNotAllowed(response)

		return
	}

	var device CreateSignatureDevice

	// Try to decode the request body into the struct. If there is an error,
	// respond to the client with the error message and a 400 status code.
	err := json.NewDecoder(request.Body).Decode(&device)

	if err != nil {
		log.Println("[WARNING][CreateSignatureDevice] decode error", err)
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			"Invalid request body was sent",
		})
		return
	}

	err = s.v.Struct(&device)
	if err != nil {
		log.Println("[WARNING][CreateSignatureDevice] decode error", err)
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			"Invalid request body was sent",
		})
		return
	}

	res, err := s.signature.CreateDevice(request.Context(), device.ConvertToDomain())
	if err != nil {
		if errors.Is(err, domain.ErrDeviceAlreadyExist) {
			WriteErrorResponse(response, http.StatusConflict, []string{
				domain.ErrDeviceAlreadyExist.Error(),
			})

			return
		}
		WriteInternalError(response)

		return
	}

	WriteAPIResponse(response, http.StatusOK, struct {
		ID uuid.UUID `json:"id"`
	}{
		ID: res,
	})
}

// ConvertToDomain converts CreateSignatureDevice to domain.Device
func (d CreateSignatureDevice) ConvertToDomain() domain.Device {
	return domain.Device{
		ID:        d.ID,
		Algorithm: getAlgorithm(d.Algorithm),
		Label:     d.Label,
	}
}

func getAlgorithm(algorithm Algorithm) domain.Algorithm {
	switch algorithm {
	case RSA:
		return domain.RSA
	case ECC:
		return domain.ECDSA
	default:
		return domain.ECDSA
	}
}
