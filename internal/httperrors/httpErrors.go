package httperrors

import (
	"net/http"
)

type Error struct {
	err    error
	status int
}

func NewError(err error, status int) error {
	e := &Error{
		err:    err,
		status: status,
	}
	return e
}

func (e *Error) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return e.Message()
}

func (e *Error) Message() string {
	switch e.status {
	case http.StatusBadRequest:
		return "The request was invalid"
	case http.StatusUnauthorized:
		return "Unauthorized"
	case http.StatusForbidden:
		return "You do not have enough permissions"
	case http.StatusNotFound:
		return "The requested resource was not found"
	case http.StatusMethodNotAllowed:
		return "Method Not Allowed"
	case http.StatusConflict:
		return "Duplicate entry"
	default:
		return "Something went wrong"
	}
}

func (e *Error) Status() int {
	if e.status >= http.StatusBadRequest {
		return e.status
	}

	return http.StatusInternalServerError
}

func (e *Error) Unwrap() error {
	return e.err
}
