package core

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
)

type Backend interface {
	Get(r *http.Request) (body []byte, content_type string, err error)
	Put(r *http.Request) (err error)
	Delete(r *http.Request) (err error)
	PropFind(r *http.Request, pf *PropFind, depth byte) (ms *MultiStatus, err error)
	PropPatch(r *http.Request, property_update *PropertyUpdate) (ms *MultiStatus, err error)
	MkCol(r *http.Request, props []Prop) (resp []PropStat, err error)
	Query(r *http.Request, query *Query, depth byte) (ms *MultiStatus, err error)
	Multiget(r *http.Request, multiget *Multiget) (ms *MultiStatus, err error)
	Options(r *http.Request) (caps []string, allow []string)
}

type Handler struct {
	Backend Backend
}

func (h *Handler) serveOptions(caps []string, allow []string, w http.ResponseWriter, r *http.Request) {
	if caps != nil {
		w.Header().Add("DAV", strings.Join(caps, ", "))
	}
	w.Header().Add("Allow", strings.Join(allow, ", "))
	w.WriteHeader(http.StatusOK)
	w.Write(nil)
}

func (h *Handler) handleHeadGet(w http.ResponseWriter, r *http.Request, headonly bool) error {
	body, content_type, err := h.Backend.Get(r)
	if err != nil {
		return err
	}
	w.Header().Add("Content-Type", content_type)

	if !headonly {
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	} else {
		w.WriteHeader(http.StatusNoContent)
		w.Write(nil)
	}
	return nil
}

func (h *Handler) handlePut(w http.ResponseWriter, r *http.Request) error {
	if e := h.Backend.Put(r); e != nil {
		return e
	} else {
		w.WriteHeader(http.StatusCreated)
		w.Write(nil)
		return nil
	}
}

func (h *Handler) handleMkCol(w http.ResponseWriter, r *http.Request) error {
	mkcol := &mkColRequest{}
	if isXML, e := isContentXML(r.Header); e != nil {
		return e
	} else if isXML {
		if e := xml.NewDecoder(r.Body).Decode(mkcol); e != nil {
			return &webDAVerror{
				Code: http.StatusBadRequest,
			}
		}
	}

	if resp, e := h.Backend.MkCol(r, mkcol.Props); e != nil {
		return e
	} else {
		switch r.Method {
		case "MKCOL":
			if v, e := xml.Marshal(&mkColResponse{PropStats: resp}); e != nil {
				return e
			} else {
				if len(resp) != 0 {
					w.WriteHeader(http.StatusForbidden)
					w.Write(v)
				} else {
					w.WriteHeader(http.StatusCreated)
					w.Write(nil)
				}
				return nil
			}
		case "MKCALENDAR":
			if v, e := xml.Marshal(&mkCalendarResponse{PropStats: resp}); e != nil {
				return e
			} else {
				if len(resp) != 0 {
					w.WriteHeader(http.StatusForbidden)
					w.Write(v)
				} else {
					w.WriteHeader(http.StatusCreated)
					w.Write(nil)
				}
				return nil
			}
		default:
			panic("unknown method")
		}
	}
}

func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request) error {
	if e := h.Backend.Delete(r); e != nil {
		return e
	} else {
		w.WriteHeader(http.StatusNoContent)
		w.Write(nil)
		return nil
	}
}

func (h *Handler) handlePropPatch(w http.ResponseWriter, r *http.Request) error {
	pp := &PropertyUpdate{}
	if isXML, e := isContentXML(r.Header); e != nil {
		return e
	} else if isXML {
		if e := xml.NewDecoder(r.Body).Decode(pp); e != nil {
			return &webDAVerror{
				Code: http.StatusBadRequest,
			}
		}
	}

	if ms, e := h.Backend.PropPatch(r, pp); e != nil {
		return e
	} else {
		if buf := bytes.NewBufferString(xml.Header); false {
			//
		} else if e := xml.NewEncoder(buf).Encode(ms); e != nil {
			return e
		} else {
			w.Header().Add("Content-Type", "text/xml; charset=utf-8")
			w.WriteHeader(http.StatusMultiStatus)
			w.Write(buf.Bytes())
		}
		return nil
	}
}

func (h *Handler) handlePropFind(w http.ResponseWriter, r *http.Request) error {
	pf := &PropFind{}
	var depth byte
	if isXML, e := isContentXML(r.Header); e != nil {
		return e
	} else if isXML {
		if e := xml.NewDecoder(r.Body).Decode(pf); e != nil {
			return &webDAVerror{
				Code: http.StatusBadRequest,
			}
		}
	} else {
		var b [1]byte
		if _, err := r.Body.Read(b[:]); err != io.EOF {
			// http.StatusBadRequest
			return &webDAVerror{
				Code: http.StatusBadRequest,
			}
		} else {
			// no body; assume allprop
			pf.AllProp = &struct{}{}
		}
	}
	switch r.Header.Get("Depth") {
	case "0":
		depth = 0
	case "1":
		depth = 1
	default:
		depth = 2
	}

	if ms, e := h.Backend.PropFind(r, pf, depth); e != nil {
		return e
	} else {
		if buf := bytes.NewBufferString(xml.Header); false {
			//
		} else if e := xml.NewEncoder(buf).Encode(ms); e != nil {
			return e
		} else {
			w.Header().Add("Content-Type", "text/xml; charset=utf-8")
			w.WriteHeader(http.StatusMultiStatus)
			w.Write(buf.Bytes())
		}
		return nil
	}
}

func (h *Handler) handleReport(w http.ResponseWriter, r *http.Request) (err error) {
	report := &reportReq{}
	if isXML, e := isContentXML(r.Header); e != nil {
		err = e
	} else if isXML {
		err = xml.NewDecoder(r.Body).Decode(report)
	} else if !isXML {
		err = &webDAVerror{
			Code: http.StatusUnsupportedMediaType,
		}
	}
	if err != nil {
		return err
	}

	var depth byte

	// for some reason default depth (used for Query) is 0
	switch r.Header.Get("Depth") {
	case "infinity":
		depth = 2
	case "1":
		depth = 1
	default:
		depth = 0
	}

	var ms *MultiStatus
	if report.Query != nil {
		ms, err = h.Backend.Query(r, report.Query, depth)
	} else if report.Multiget != nil {
		ms, err = h.Backend.Multiget(r, report.Multiget)
	}

	if err != nil {
		return err
	} else if ms == nil {
		panic("nil multistatus but no error")
	}

	buf := bytes.NewBufferString(xml.Header)

	if e := xml.NewEncoder(buf).Encode(ms); e != nil {
		return e
	} else {
		w.Header().Add("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusMultiStatus)
		w.Write(buf.Bytes())
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	caps, allow := h.Backend.Options(r)
	for _, a := range allow {
		if r.Method == a {
			goto mux
		}
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
	w.Write(nil)
	return
mux:
	switch r.Method {
	case http.MethodOptions:
		h.serveOptions(caps, allow, w, r)
	case "PROPFIND":
		err = h.handlePropFind(w, r)
	case "REPORT":
		err = h.handleReport(w, r)
	case http.MethodHead:
		err = h.handleHeadGet(w, r, true)
	case http.MethodGet:
		err = h.handleHeadGet(w, r, false)
	case http.MethodPut:
		err = h.handlePut(w, r)
	case http.MethodDelete:
		err = h.handleDelete(w, r)
	case "PROPPATCH":
		err = h.handlePropPatch(w, r)
	case "MKCALENDAR", "MKCOL":
		err = h.handleMkCol(w, r)
	case "COPY", "MOVE":
		// copy (or move) does not make sense within a collection
		// but it does make sense when spanning two different collections
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write(nil)
	}
	if err == nil {
		return
	}
	var code int
	var body []byte
	if e, ok := err.(*webDAVerror); ok {
		code = e.Code
		if e.Condition == nil {
			// no condition given
		} else if b, e := xml.Marshal(wrapError(*e.Condition, e.Content)); e != nil {
			panic(e)
		} else {
			w.Header().Add("Content-Type", "text/xml; charset=utf-8")
			body = b
		}
	} else if uc, ok := err.(*UidConflict); ok {
		code = http.StatusForbidden
		condition := Any{}
		if b, e := xml.Marshal(uc.Href); e != nil {
			panic(e)
		} else {
			condition.Content = b
			switch uc.Scope {
			case CalendarScope:
				condition.XMLName = calendarNoUIDConflictName
			case AddressbookScope:
				condition.XMLName = addressbookNoUIDConflictName
			}
		}
		if b, e := xml.Marshal(&davError{Conditions: []Any{condition}}); e != nil {
			panic(e)
		} else {
			w.Header().Add("Content-Type", "text/xml; charset=utf-8")
			body = b
		}
	} else {
		code = http.StatusInternalServerError
	}
	w.WriteHeader(code)
	w.Write(body)
}
