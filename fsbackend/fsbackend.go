package fsbackend

import (
	"bufio"
	"bytes"
	"encoding/base32"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"

	"bq-caldav/core"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-vcard"
	"github.com/gabriel-vasile/mimetype"
)

type FSBackend struct {
	create func(p string) (io.WriteCloser, error)
	mkdir  func(p string) error
	delete func(p string) error
	fsys   fs.FS
	uidmap map[string]string
	lock   *sync.Mutex
}

func NewBackend(location string) *FSBackend {
	if e := os.MkdirAll(path.Join(location, "calendars"), os.ModePerm); e != nil {
		panic(e)
	} else if e := os.MkdirAll(path.Join(location, "addressbook"), os.ModePerm); e != nil {
		panic(e)
	}
	fsys := os.DirFS(location)
	br := new(bufio.Reader)
	uidmap := make(map[string]string)
	if e := fs.WalkDir(fsys, ".", func(q string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() || path.Base(q) == "props.xml" {
			return nil
		} else if f, e := fsys.Open(q); e != nil {
			return e
		} else {
			br.Reset(f)
			for {
				if l, e := br.ReadSlice('\n'); e == nil {
					if !bytes.HasPrefix(l, []byte("UID:")) {
						continue
					} else if l = bytes.TrimSpace(l[4:]); true {
						uidmap[fmt.Sprintf("%s:%s", path.Dir(q), l)] = "/" + q
						return nil
					}
				} else {
					return nil
				}
			}
		}
	}); e != nil {
		panic(e)
	}
	return &FSBackend{
		create: func(p string) (io.WriteCloser, error) {
			return os.Create(path.Join(location, p))
		},
		mkdir: func(p string) error {
			return os.Mkdir(path.Join(location, p), os.ModePerm)
		},
		delete: func(p string) error {
			return os.RemoveAll(path.Join(location, p))
		},
		fsys:   os.DirFS(location),
		uidmap: uidmap,
		lock:   new(sync.Mutex),
	}
}

type notFound struct{}

func (err *notFound) Error() string {
	return http.StatusText(http.StatusNotFound)
}

// GET or HEAD
func (b *FSBackend) Get(r *http.Request) (body []byte, content_type string, err error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	p := path.Clean(r.URL.Path)[1:]
	if p == "me.vcf" {
		body, content_type = b.medotvcf()
		err = nil
		return
	}

	if path.Base(p) == "props.xml" {
		err = core.WebDAVerror(http.StatusNotFound, nil)
	} else if fi, e := fs.Stat(b.fsys, p); e != nil {
		err = core.WebDAVerror(http.StatusNotFound, nil)
	} else if fi.IsDir(); e != nil {
		err = core.WebDAVerror(http.StatusMethodNotAllowed, nil)
	} else if etag, mt, _, b, e := b.getETagMTCLBody(p); e != nil {
		// potentially bubble up to internal server error
		// but probably not
		log.Println("unexpected error: ", e.Error())
		err = e
	} else if e := core.IfMatchifNoneMatch(etag, r.Header.Get("If-Match"), r.Header.Get("If-None-Match")); e != nil {
		err = e
	} else {
		content_type = mt.String()
		body = b
	}
	return
}

func (b *FSBackend) medotvcf() (body []byte, content_type string) {
	me := vcard.Card{}
	if f, e := b.fsys.Open("me.vcf"); e != nil {
		//
	} else if m, e := vcard.NewDecoder(f).Decode(); e != nil {
		//
	} else {
		me = m
		goto jump
	}

	me.Set(vcard.FieldFormattedName, &vcard.Field{Value: "Default"})
jump:
	vcard.ToV4(me)
	buf := bytes.NewBuffer(nil)
	if e := vcard.NewEncoder(buf).Encode(me); e != nil {
		panic(e)
	}
	return buf.Bytes(), "text/vcard"
}

// DELETE
func (b *FSBackend) Delete(r *http.Request) (err error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	p := path.Clean(r.URL.Path)[1:]
	if fi, e := fs.Stat(b.fsys, p); e != nil || path.Base(p) == "props.xml" {
		return core.WebDAVerror(http.StatusNotFound, nil)
	} else if fi.IsDir() {
		return b.delete(p)
	} else if etag, _, _, current_body, e := b.getETagMTCLBody(p); e != nil {
		return e
	} else if e := core.IfMatchifNoneMatch(etag, r.Header.Get("If-Match"), r.Header.Get("If-None-Match")); e != nil {
		return err
	} else if e := b.delete(p); e != nil {
		return e
	} else {
		// delete from uidmap if it is a UID object
		if s := bytes.Index(current_body, []byte("UID:")); s == -1 {
			// do nothing
		} else if t := bytes.Index(current_body[s+4:], []byte{'\r', '\n'}); t == -1 {
			// do nothing
		} else {
			// delete from uidmap
			delete(b.uidmap, fmt.Sprintf("%s:%s", path.Dir(p), current_body[s+4:s+4+t]))
		}
	}
	return nil
}

// MKCOL
func (b *FSBackend) MkCol(r *http.Request, prop_req []core.Prop) (resp []core.PropStat, err error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	p := path.Clean(r.URL.Path)[1:]
	if _, e := fs.Stat(b.fsys, p); !errors.Is(e, fs.ErrNotExist) {
		err = core.WebDAVerror(http.StatusConflict, &xml.Name{Space: "DAV:", Local: "resource-must-be-null"})
	} else if rsp, pw, e := core.CheckMkColReq(getScope(r.URL.Path), prop_req); e != nil {
		err = e
	} else {
		resp = rsp
		if len(resp) != 0 {
			return
		} else if e := b.mkdir(p); e != nil {
			err = e
		} else if f, e := b.create(path.Join(p, "props.xml")); e != nil {
			err = e
		} else if _, e := f.Write([]byte(xml.Header)); e != nil {
			err = e
		} else if e := xml.NewEncoder(f).Encode(pw); e != nil {
			err = e
		}
	}
	return
}

// PUT
func (b *FSBackend) Put(r *http.Request) (err error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	p := path.Clean(r.URL.Path)[1:]
	if _, e := fs.Stat(b.fsys, path.Dir(p)); e != nil {
		err = core.WebDAVerror(http.StatusConflict, nil)
	}

	var body io.Reader
	switch path.Dir(path.Dir(p)) {
	case "calendars":
		if cal, e := core.CheckCalendarDataSupportedAndValid(r.Header.Get("Content-Type"), r.Body); e != nil {
			err = e
		} else if b, e := b.checkCalendarObject(r, p, cal); e != nil {
			err = e
		} else {
			body = b
		}
	case "addressbook":
		if card, e := core.CheckAddressDataSupportedAndValid(r.Header.Get("Content-Type"), r.Body); e != nil {
			err = e
		} else if b, e := b.checkAddressObject(r, p, card); e != nil {
			err = e
		} else {
			body = b
		}
	default:
		switch getScope(r.URL.Path) {
		case core.CalendarScope:
			err = core.WebDAVerror(http.StatusForbidden, &xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "calendar-collection-location-ok"})
		case core.AddressbookScope:
			err = core.WebDAVerror(http.StatusForbidden, &xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "addressbook-collection-location-ok"})
		}
	}

	if err != nil {
		return
	}

	if f, e := b.create(p); e != nil {
		err = e
	} else if _, e := io.Copy(f, body); e != nil {
		err = e
	} else if e := f.Close(); e != nil {
		err = e
	}
	return
}

// only used in PUT request
func (b *FSBackend) checkCalendarObject(r *http.Request, p string, cal *ical.Calendar) (io.Reader, error) {
	// if `if-match` or `if-none-match` fails return 412 precondition failed
	// https://datatracker.ietf.org/doc/html/rfc7232
	//

	collection_prop := &core.Prop{}
	if pf, e := b.fsys.Open(path.Join(path.Dir(p), "props.xml")); e != nil {
		return nil, core.WebDAVerror(http.StatusForbidden, &xml.Name{
			Space: "urn:ietf:params:xml:ns:caldav",
			Local: "calendar-collection-location-ok",
		})
	} else if e := xml.NewDecoder(pf).Decode(collection_prop); e != nil {
		return nil, e
	}

	etag, mt, _, current_body, _ := b.getETagMTCLBody(p)
	// don't bother checking the error; etag == "" if the file does not exist

	if e := core.IfMatchifNoneMatch(etag, r.Header.Get("If-Match"), r.Header.Get("If-None-Match")); e != nil {
		return nil, e
	}

	// check additional caldav preconditions
	// https://datatracker.ietf.org/doc/html/rfc4791#section-5.3.2.1
	//
	buf := bytes.NewBuffer(nil)

	loc, err := core.GetLocationFromProp(collection_prop)
	if err != nil {
		return nil, err
	}

	// should pass calendar-timezone if it exists instead of `nil`
	if md, e := core.ParseCalendarObjectResource(cal, loc); e != nil {
		return nil, e
	} else if e := core.CheckCalendarCompIsSupported(collection_prop, md.ComponentType); e != nil {
		return nil, e
	} else if uid, e := md.GetUID(); e != nil {
		return nil, e
	} else if v, ok := b.uidmap[path.Dir(p)+":"+uid]; ok && v != r.URL.Path {
		return nil, &core.UidConflict{Scope: core.CalendarScope, Href: core.Href{Target: v}}
	} else if d := bytes.Index(current_body, []byte(uid)); mt != nil && mt.Is(ical.MIMEType) && d == -1 {
		return nil, &core.UidConflict{Scope: core.CalendarScope, Href: core.Href{Target: r.URL.Path}}
	} else if e := ical.NewEncoder(buf).Encode(cal); e != nil {
		return nil, core.WebDAVerror(http.StatusInternalServerError, nil)
	} else if e := core.CheckMaxResourceSize(collection_prop, uint64(buf.Len())); e != nil {
		return nil, e
	} else if e := core.CheckOtherCalendarPreconditions(collection_prop, md); e != nil {
		return nil, e
	} else {
		b.uidmap[path.Dir(p)+":"+uid] = r.URL.Path
	}

	return buf, nil
}

func (b *FSBackend) checkAddressObject(r *http.Request, p string, card vcard.Card) (io.Reader, error) {
	// if `if-match` or `if-none-match` fails return 412 precondition failed
	// https://datatracker.ietf.org/doc/html/rfc7232
	//
	etag, mt, _, current_body, _ := b.getETagMTCLBody(p)
	// don't bother checking the error; etag == "" if the file does not exist

	if e := core.IfMatchifNoneMatch(etag, r.Header.Get("If-Match"), r.Header.Get("If-None-Match")); e != nil {
		return nil, e
	}

	collection_prop := &core.Prop{}
	if pf, e := b.fsys.Open(path.Join(path.Dir(p), "props.xml")); e != nil {
		return nil, core.WebDAVerror(http.StatusForbidden, &xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "addressbook-collection-location-ok"})
	} else if e := xml.NewDecoder(pf).Decode(collection_prop); e != nil {
		return nil, e
	}

	buf := bytes.NewBuffer(nil)
	if f := card.Get(vcard.FieldUID); f == nil {
		// should have already checked this earlier in the handling
		panic("vcard is missing UID")
	} else if uid := f.Value; false {
		//
	} else if v, ok := b.uidmap[path.Dir(p)+":"+uid]; ok && v != r.URL.Path {
		return nil, &core.UidConflict{Scope: core.AddressbookScope, Href: core.Href{Target: v}}
	} else if d := bytes.Index(current_body, []byte(uid)); mt != nil && mt.Is(ical.MIMEType) && d == -1 {
		return nil, &core.UidConflict{Scope: core.AddressbookScope, Href: core.Href{Target: r.URL.Path}}
	} else if e := vcard.NewEncoder(buf).Encode(card); e != nil {
		return nil, core.WebDAVerror(http.StatusInternalServerError, nil)
	} else if e := core.CheckMaxResourceSize(collection_prop, uint64(buf.Len())); e != nil {
		return nil, e
	} else {
		b.uidmap[path.Dir(p)+":"+uid] = r.URL.Path
	}

	return buf, nil
}

// PROPPATCH
func (b *FSBackend) PropPatch(r *http.Request, property_update *core.PropertyUpdate) (ms *core.MultiStatus, err error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	p := path.Clean(path.Join(r.URL.Path, "props.xml"))[1:]

	current_prop := &core.Prop{}
	if f, e := b.fsys.Open(p); e != nil {
		err = core.WebDAVerror(http.StatusNotFound, nil)
	} else if e := xml.NewDecoder(f).Decode(current_prop); e != nil {
		err = e
	}
	if err != nil {
		return
	}

	// return ms, and record new_prop (reusing current_prop struct)
	ms, current_prop = core.PropPatchHelper(getScope(r.URL.Path), current_prop, property_update)

	if current_prop == nil {
		return
	}

	// write the new props.xml file
	if f, e := b.create(p); e != nil {
		err = e
	} else if _, e := f.Write([]byte(xml.Header)); e != nil {
		err = e
	} else if e := xml.NewEncoder(f).Encode(current_prop); e != nil {
		err = e
	}
	return
}

// PROPFIND
func (b *FSBackend) PropFind(r *http.Request, pf *core.PropFind, depth byte) (ms *core.MultiStatus, err error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	ms = &core.MultiStatus{}
	p := path.Clean(r.URL.Path)[1:]
	if p == "" {
		p = "."
	}
	if stat, e := fs.Stat(b.fsys, p); e != nil {
		return nil, core.WebDAVerror(http.StatusNotFound, nil)
	} else if !stat.IsDir() || depth == 0 {
		if resp, e := b.propFindResource(p, stat, pf); e != nil {
			return nil, e
		} else {
			ms.Responses = []core.Response{*resp}
			return
		}
	}
	resps := make([]core.Response, 0, 128)
	err = fs.WalkDir(b.fsys, p, func(q string, de fs.DirEntry, err error) error {
		if err != nil {
			return nil
		} else if fi, e := de.Info(); e != nil {
			return nil
		} else if resp, e := b.propFindResource(q, fi, pf); e != nil {
			if !errors.Is(e, &notFound{}) {
				return e
			} else {
				// do not fail if NotFound, since walking dir
				return nil
			}
		} else {
			resps = append(resps, *resp)
		}
		if depth == 1 && de.IsDir() && len(p) < len(q) {
			return fs.SkipDir
		}
		return nil
	})
	ms.Responses = resps
	return
}

func (b *FSBackend) propFindResource(p string, fi fs.FileInfo, pf *core.PropFind) (resp *core.Response, err error) {
	var props_Found []core.Any
	if fi.IsDir() {
		props_Found, err = b.propFindDir(p)
	} else {
		props_Found, _, err = b.propFindFile(p, fi)
	}
	if err != nil {
		return
	}

	if p == "." {
		p = "/"
	} else {
		p = "/" + p
	}
	return &core.Response{
		PropStats: core.CleanProps(getScope(p), props_Found, pf.PropName, pf.Include, pf.AllProp, pf.Prop),
		Hrefs:     []core.Href{{Target: p}},
	}, nil
}

func getScope(p string) core.Scope {
	if p == "/" {
		return core.CalendarScope | core.AddressbookScope
	}
	components := strings.Split(strings.TrimPrefix(p, "/"), "/")
	switch components[0] {
	case "calendars":
		return core.CalendarScope
	case "addressbook":
		return core.AddressbookScope
	default:
		return 0
	}
}

func (b *FSBackend) propFindDir(p string) (props_Found []core.Any, err error) {
	if p == "." {
		return core.DefaultPropsRoot(), nil
	}

	if p == "calendars" || p == "addressbook" {
		return core.DefaultPropsHomeSet(), nil
	}

	if d, _ := path.Split(p); d != "calendars/" && d != "addressbook/" {
		return nil, &notFound{}
	} else {
		prop := &core.Prop{}
		if f, e := b.fsys.Open(path.Join(p, "props.xml")); e != nil {
			return nil, &notFound{}
		} else if e := xml.NewDecoder(f).Decode(prop); e != nil {
			// bubble up internal server error
			return nil, e
		}
		switch d {
		case "calendars/":
			props_Found = core.MarshalPropsCalendarCollection(prop)
		case "addressbook/":
			props_Found = core.MarshalPropsAddressbookCollection(prop)
		}
	}

	return
}

func (b *FSBackend) getETagMTCLBody(p string) (etag string, mt *mimetype.MIME, content_length int64, body []byte, err error) {
	buf := bytes.NewBuffer(nil)

	if f, e := b.fsys.Open(p); e != nil {
		err = &notFound{}
		return
	} else {
		h := fnv.New32a()
		if n, e := io.Copy(buf, io.TeeReader(f, h)); e != nil {
			err = e
			return
		} else if e := f.Close(); e != nil {
			err = e
			return
		} else {
			content_length = n
		}
		etag = base32.StdEncoding.EncodeToString(h.Sum(nil))[:7]
	}
	mt = mimetype.Detect(buf.Bytes())
	body = buf.Bytes()
	return
}

func (b *FSBackend) propFindFile(p string, fi fs.FileInfo) (props_Found []core.Any, body []byte, err error) {
	if path.Base(p) == "props.xml" {
		return nil, nil, &notFound{}
	}

	var etag string
	var mt_string string
	var content_length int64
	if et, mt, cl, br, e := b.getETagMTCLBody(p); e != nil {
		err = e
		return
	} else {
		etag = et
		content_length = cl
		mt_string = mt.String()
		body = br
	}
	props_Found = core.DefaultPropsFile(mt_string, content_length, fi.ModTime(), etag)
	return
}

// REPORT calendar-query or addressbook-query
func (b *FSBackend) Query(r *http.Request, query *core.Query, depth byte) (ms *core.MultiStatus, err error) {
	query_scope := query.Scope()
	p := path.Clean(r.URL.Path)[1:]
	if p == "" {
		p = "."
	}
	b.lock.Lock()
	defer b.lock.Unlock()

	switch getScope(r.URL.Path) {
	case core.CalendarScope:
		if query_scope != core.CalendarScope {
			err = core.WebDAVerror(http.StatusBadRequest, nil)
			return
		} else if query.Timezone == nil {
			// need to get timezone
			err = core.WebDAVerror(http.StatusMethodNotAllowed, nil)
			var propsdotxmlpath string
			if d := len(strings.Split(p, "/")); d == 2 {
				propsdotxmlpath = path.Join(p, "props.xml")
			} else if d == 3 {
				propsdotxmlpath = path.Join(path.Dir(p), "props.xml")
			} else {
				return
			}
			err = core.WebDAVerror(http.StatusInternalServerError, nil)
			collection_prop := &core.Prop{}
			if pf, e := b.fsys.Open(propsdotxmlpath); e != nil {
				return
			} else if e := xml.NewDecoder(pf).Decode(collection_prop); e != nil {
				return
			} else if loc, e := core.GetLocationFromProp(collection_prop); e != nil {
				return
			} else {
				err = nil
				query.Timezone = &core.Timezone{Location: loc}
			}
		}
		if cd, e := core.ParseCalendarData(query); e != nil {
			err = e
			return
		} else {
			query.CalendarData = cd
		}
	case core.AddressbookScope:
		if query_scope != core.AddressbookScope {
			err = core.WebDAVerror(http.StatusBadRequest, nil)
			return
		}
	}
	ms = &core.MultiStatus{}

	if fi, e := fs.Stat(b.fsys, p); e != nil {
		// empty return means empty multistatus
		// which is the expected behavior
		return
	} else if fi.IsDir() && depth == 0 {
		return
	} else if depth == 0 {
		if resp, match, e := b.queryFile(p, fi, query); !match || e != nil {
			if !errors.Is(e, &notFound{}) {
				// this could return a not-implemented error
				// if the client tries a not-implemented query
				err = e
			}
			return
		} else {
			ms.Responses = []core.Response{*resp}
			return
		}
	}
	resps := make([]core.Response, 0, 128)
	err = fs.WalkDir(b.fsys, p, func(q string, de fs.DirEntry, err error) error {
		if depth == 1 && de.IsDir() && len(p) < len(q) {
			return fs.SkipDir
		} else if err != nil || de.IsDir() {
			return nil
		} else if fi, e := de.Info(); e != nil {
			return nil
		} else if resp, match, e := b.queryFile(q, fi, query); e != nil || !match {
			if !errors.Is(e, &notFound{}) {
				return e
			}
			return nil
		} else {
			resps = append(resps, *resp)
		}
		return nil
	})
	ms.Responses = resps
	return
}

func (b *FSBackend) queryFile(p string, fi fs.FileInfo, query *core.Query) (resp *core.Response, match bool, err error) {
	var file io.Reader
	var props_Found []core.Any
	if pf, f, e := b.propFindFile(p, fi); e != nil {
		err = e
		return
	} else {
		file = bytes.NewBuffer(f)
		props_Found = pf
	}
	switch query.Scope() {
	case core.CalendarScope:
		// now check if the file matches the query
		if cal, e := ical.NewDecoder(file).Decode(); e != nil {
			err = core.WebDAVerror(http.StatusInternalServerError, nil)
			return
		} else if m, e := core.MatchCalendarWithQuery(cal, query); e != nil {
			// webdav error such as: not-implemented or bad-request
			err = e
			return
		} else if !m {
			// did not match
			err = &notFound{}
			return
		} else if a, e := core.CalendarData(cal, query.CalendarData, query.Timezone.Location); e != nil {
			// internal server error or webdav not-implemented
			err = e
			return
		} else if a != nil {
			props_Found = append(props_Found, *a)
		}
	case core.AddressbookScope:
		// todo: filter via query
		if card, e := vcard.NewDecoder(file).Decode(); e != nil {
			return
		} else if a, e := core.AddressData(card, query.Prop); e != nil {
			return
		} else if a != nil {
			props_Found = append(props_Found, *a)
		}
	default:
		panic("unknown scope")
	}

	if p == "." {
		p = "/"
	} else {
		p = "/" + p
	}

	// clean up the props
	propstats := core.CleanProps(getScope(p), props_Found, query.PropName, nil, query.AllProp, query.Prop)

	return &core.Response{
		PropStats: propstats,
		Hrefs:     []core.Href{{Target: p}},
	}, true, nil
}

// REPORT calendar-multiget
func (b *FSBackend) Multiget(r *http.Request, multiget *core.Multiget) (ms *core.MultiStatus, err error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	p := path.Clean(r.URL.Path)[1:]
	if p == "" {
		p = "."
	}

	scope := multiget.Scope()
	switch getScope(r.URL.Path) {
	case core.CalendarScope:
		if scope != core.CalendarScope {
			err = core.WebDAVerror(http.StatusBadRequest, nil)
			return
		}
		if multiget.Timezone == nil {
			// need to get timezone
			err = core.WebDAVerror(http.StatusMethodNotAllowed, nil)
			var propsdotxmlpath string
			if d := len(strings.Split(p, "/")); d == 2 {
				propsdotxmlpath = path.Join(p, "props.xml")
			} else if d == 3 {
				propsdotxmlpath = path.Join(path.Dir(p), "props.xml")
			} else {
				return
			}
			err = core.WebDAVerror(http.StatusInternalServerError, nil)
			collection_prop := &core.Prop{}
			if pf, e := b.fsys.Open(propsdotxmlpath); e != nil {
				return
			} else if e := xml.NewDecoder(pf).Decode(collection_prop); e != nil {
				return
			} else if loc, e := core.GetLocationFromProp(collection_prop); e != nil {
				return
			} else {
				err = nil
				multiget.Timezone = &core.Timezone{Location: loc}
			}
		}
		if cd, e := core.ParseCalendarData(multiget); e != nil {
			err = e
			return
		} else {
			multiget.CalendarData = cd
		}

	case core.AddressbookScope:
		if scope != core.AddressbookScope {
			err = core.WebDAVerror(http.StatusBadRequest, nil)
			return
		}
	}

	var resps []core.Response

	if fi, e := fs.Stat(b.fsys, p); e != nil {
		return
	} else if !fi.IsDir() {
		if resp, e := b.multigetFile(p, fi, multiget); e != nil {
			goto jump
		} else {
			resps = []core.Response{*resp}
			goto jump
		}
	}
	// depth is infinite

	resps = make([]core.Response, 0, 128)
	fs.WalkDir(b.fsys, p, func(q string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return nil
		} else if fi, e := de.Info(); e != nil {
			return nil
		} else if resp, e := b.multigetFile(q, fi, multiget); e != nil {
			return nil
		} else {
			resps = append(resps, *resp)
		}
		return nil
	})
jump:
	ms = core.MarshalMultigetRespose(multiget, resps)
	return
}

func (b *FSBackend) multigetFile(p string, fi fs.FileInfo, multiget *core.Multiget) (resp *core.Response, err error) {
	for _, href := range multiget.Hrefs {
		if path.Clean(href.Target)[1:] == p {
			goto jump
		}
	}
	return nil, &notFound{}
jump:
	var file io.Reader
	var props_Found []core.Any
	if pf, f, e := b.propFindFile(p, fi); e != nil {
		err = e
		return
	} else {
		file = bytes.NewBuffer(f)
		props_Found = pf
	}

	switch multiget.Scope() {
	case core.CalendarScope:
		// now write calendar-data
		if cal, e := ical.NewDecoder(file).Decode(); e != nil {
			err = &notFound{}
			return
		} else if a, e := core.CalendarData(cal, multiget.CalendarData, multiget.Timezone.Location); e != nil {
			err = e
			return
		} else if a != nil {
			props_Found = append(props_Found, *a)
		}
	case core.AddressbookScope:
		if card, e := vcard.NewDecoder(file).Decode(); e != nil {
			err = &notFound{}
			return
		} else if a, e := core.AddressData(card, multiget.Prop); e != nil {
			// todo: handle this better
			err = &notFound{}
			return
		} else if a != nil {
			props_Found = append(props_Found, *a)
		}
	default:
		panic("unknown scope")
	}

	// clean up the props
	if p == "." {
		p = "/"
	} else {
		p = "/" + p
	}
	propstats := core.CleanProps(getScope(p), props_Found, multiget.PropName, nil, multiget.AllProp, multiget.Prop)
	return &core.Response{
		PropStats: propstats,
		Hrefs:     []core.Href{{Target: p}},
	}, nil
}

// OPTIONS
func (b *FSBackend) Options(r *http.Request) (caps []string, allow []string) {
	p := path.Clean(r.URL.Path)

	if p == "/" {
		caps = []string{"1", "3", "calendar-access", "addressbook", "extended-mkcol"}
		allow = []string{http.MethodOptions, "PROPFIND"}
		return
	} else if p == "/me.vcf" {
		caps = []string{"1"}
		allow = []string{http.MethodOptions, "PROPFIND", "GET", "HEAD", "PUT", "DELETE"}
	}

	p = p[1:]
	components := strings.Split(p, "/")
	if components[0] == "calendars" {
		caps = []string{"1", "3", "calendar-access", "extended-mkcol"}
		switch len(components) {
		case 1: // path targets /calendars
			allow = []string{http.MethodOptions, "PROPFIND"}
		case 2: // path targets /calendars/X
			allow = []string{http.MethodOptions, "PROPFIND", "REPORT", "PROPPATCH", "MKCOL", "MKCALENDAR", "DELETE"}
		case 3: // path targets /calendars/X/Y
			allow = []string{http.MethodOptions, "PROPFIND", "REPORT", "DELETE", "PUT", "GET", "HEAD"}
		}
	} else if components[0] == "addressbook" {
		caps = []string{"1", "3", "addressbook", "extended-mkcol"}
		switch len(components) {
		case 1: // path targets /addressbook
			allow = []string{http.MethodOptions, "PROPFIND"}
		case 2: // path targets /addressbook/X
			allow = []string{http.MethodOptions, "PROPFIND", "REPORT", "PROPPATCH", "MKCOL", "DELETE"}
		case 3: // path targets /addressbook/X/Y
			allow = []string{http.MethodOptions, "PROPFIND", "REPORT", "DELETE", "PUT", "GET", "HEAD"}
		}
	}
	return
}
