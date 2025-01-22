package core

import (
	"encoding/xml"
	"net/http"
)

type webDAVerror struct {
	Code      int
	Condition *xml.Name
}

func WebDAVerror(code int, name *xml.Name) error {
	return &webDAVerror{
		Code:      code,
		Condition: name,
	}
}

func (err *webDAVerror) Error() string {
	return http.StatusText(err.Code)
}
