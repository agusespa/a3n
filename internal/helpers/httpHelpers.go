package helpers

import (
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
