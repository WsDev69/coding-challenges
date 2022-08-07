package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"

	"github.com/google/uuid"
)

type SignRequest struct {
	DeviceID uuid.UUID `json:"device_id"`
	Data     string    `json:"data"`
}

type SignResp struct {
	Signature     string `json:"signature"`
	SignatureData string `json:"signature_data"`
}

func ToSignResp(transaction domain.SignedTransaction) SignResp {
	return SignResp{
		Signature:     transaction.Signature,
		SignatureData: fmt.Sprintf("%d_%s_%s", transaction.Counter, transaction.RawData, transaction.LastSignature),
	}
}

// SignTransaction signs provided data with set earlier algorithm
func (s *Server) SignTransaction(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		WriteMethodNotAllowed(response)
		return
	}

	var device SignRequest

	// Try to decode the request body into the struct. If there is an error,
	// respond to the client with the error message and a 400 status code.
	err := json.NewDecoder(request.Body).Decode(&device)

	if err != nil {
		log.Println("[WARNING][SignTransaction] decode error", err)
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			"Invalid request body was sent",
		})
		return
	}

	err = s.v.Struct(&device)
	if err != nil {
		log.Println("[WARNING][SignTransaction] decode error", err)
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			"Invalid request body was sent",
		})
		return
	}

	resp, err := s.signature.SignTx(request.Context(), device.DeviceID, device.Data)
	if err != nil {
		log.Println("[WARN][SignTransaction] error", err)
		if errors.Is(err, domain.ErrDeviceNotFound) {
			WriteErrorResponse(response, http.StatusNotFound, []string{
				domain.ErrNotFound.Error(),
			})

			return
		}

		WriteInternalError(response)

		return
	}

	WriteAPIResponse(response, http.StatusOK, ToSignResp(resp))
}
