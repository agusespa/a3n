package helpers

import (
	"errors"
	"net"
	"net/http"
)

func GetIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Fallback in case RemoteAddr isn't in IP:port format
		return r.RemoteAddr
	}
	return ip
}

func ReadQuery(r *http.Request, param string) (string, error) {
	value := r.URL.Query().Get(param)
	if value == "" {
		err := errors.New("missing parameter: " + param)
		return "", err
	}
	return value, nil
}
