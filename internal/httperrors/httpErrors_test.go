package httperrors

import (
	"errors"
	"net/http"
	"testing"
)

func TestNewError(t *testing.T) {
	err := errors.New("test error")
	status := http.StatusBadRequest
	httpErr := NewError(err, status)

	if httpErr == nil {
		t.Fatal("expected non-nil error; got nil")
	}

	if _, ok := httpErr.(*Error); !ok {
		t.Fatal("expected *Error type")
	}
}

func TestError_Error(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		status   int
		expected string
	}{
		{"With error", errors.New("test error"), http.StatusBadRequest, "test error"},
		{"Without error", nil, http.StatusBadRequest, "The request was invalid"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpErr := &Error{err: tc.err, status: tc.status}
			if httpErr.Error() != tc.expected {
				t.Errorf("expected %q; got %q", tc.expected, httpErr.Error())
			}
		})
	}
}

func TestError_Message(t *testing.T) {
	testCases := []struct {
		status   int
		expected string
	}{
		{http.StatusBadRequest, "The request was invalid"},
		{http.StatusUnauthorized, "Unauthorized"},
		{http.StatusForbidden, "You do not have enough permissions"},
		{http.StatusNotFound, "The requested resource was not found"},
		{http.StatusMethodNotAllowed, "Method Not Allowed"},
		{http.StatusConflict, "Duplicate entry"},
		{http.StatusInternalServerError, "Something went wrong"},
	}

	for _, tc := range testCases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			httpErr := &Error{status: tc.status}
			if msg := httpErr.Message(); msg != tc.expected {
				t.Errorf("expected %q; got %q", tc.expected, msg)
			}
		})
	}
}

func TestError_Status(t *testing.T) {
	testCases := []struct {
		status   int
		expected int
	}{
		{http.StatusBadRequest, http.StatusBadRequest},
		{http.StatusInternalServerError, http.StatusInternalServerError},
		{http.StatusOK, http.StatusInternalServerError},
	}

	for _, tc := range testCases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			httpErr := &Error{status: tc.status}
			if status := httpErr.Status(); status != tc.expected {
				t.Errorf("expected %d; got %d", tc.expected, status)
			}
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	originalErr := errors.New("original error")
	httpErr := &Error{err: originalErr}

	if unwrappedErr := httpErr.Unwrap(); unwrappedErr != originalErr {
		t.Errorf("expected %v; got %v", originalErr, unwrappedErr)
	}
}
