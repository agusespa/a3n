package payload

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/agusespa/a3n/internal/httperrors"
)

func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("error: %v", err.Error())

	if customErr, ok := err.(*httperrors.Error); ok {
		http.Error(w, customErr.Message(), customErr.Status())
	} else {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func Write(w http.ResponseWriter, r *http.Request, payload any) {
	if payload == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		WriteError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(jsonBytes); err != nil {
		WriteError(w, r, err)
		return
	}
}
