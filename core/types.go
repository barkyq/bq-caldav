package core

import (
	"encoding/xml"
	"net/http"
)

type Scope uint8

// Define flags for each scope
const (
	CalendarScope    Scope = 1 << iota // 1
	AddressbookScope                   // 2 (1 << 1)
	// You can add more scopes here if needed
)

type UidConflict struct {
	Scope Scope
	Href  Href
}

type webDAVerror struct {
	Code      int
	Condition *xml.Name
	Content   []byte
}

func WebDAVerror(code int, name *xml.Name) error {
	return &webDAVerror{
		Code:      code,
		Condition: name,
	}
}

func (err *UidConflict) Error() (s string) {
	return
}

func (err *webDAVerror) Error() string {
	return http.StatusText(err.Code)
}
