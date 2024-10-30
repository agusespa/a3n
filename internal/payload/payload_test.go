package payload

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agusespa/a3n/internal/httperrors"
)

func TestWriteError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "CustomErrorBadRequest",
			err:            httperrors.NewError(errors.New("some error"), http.StatusBadRequest),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "The request was invalid",
		},
		{
			name:           "StandardError",
			err:            errors.New("some error"),
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal Server Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			WriteError(w, r, tt.err)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d; got %d", tt.expectedStatus, w.Code)
			}
			if w.Body.String() != tt.expectedBody {
				t.Errorf("expected body %q; got %q", tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestWrite(t *testing.T) {
	tests := []struct {
		name                string
		payload             interface{}
		expectedStatus      int
		expectedBody        string
		expectedContentType string
		expectedError       bool
	}{
		{
			name:                "NilPayload",
			payload:             nil,
			expectedStatus:      http.StatusOK,
			expectedContentType: "",
			expectedBody:        "",
		},
		{
			name:                "ValidPayload",
			payload:             map[string]string{"message": "success"},
			expectedStatus:      http.StatusOK,
			expectedContentType: "application/json",
			expectedBody:        `{"message":"success"}`,
		},
		{
			name:                "UnmarshalablePayload",
			payload:             make(chan int),
			expectedStatus:      http.StatusInternalServerError,
			expectedContentType: "text/plain",
			expectedBody:        "Internal Server Error",
			expectedError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			Write(w, r, tt.payload, nil)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d; got %d", tt.expectedStatus, w.Code)
			}
			if w.Body.String() != tt.expectedBody {
				t.Errorf("expected body %q; got %q", tt.expectedBody, w.Body.String())
			}

			if tt.payload != nil {
				if contentType := w.Header().Get("Content-Type"); contentType != tt.expectedContentType {
					t.Errorf("expected Content-Type %q; got %q", tt.expectedContentType, contentType)
				}
				if !tt.expectedError {
					if contentLength := w.Header().Get("Content-Length"); contentLength != fmt.Sprintf("%d", len(tt.expectedBody)) {
						t.Errorf("expected Content-Length %d; got %s", len(tt.expectedBody), contentLength)
					}
				}
			}
		})
	}
}
