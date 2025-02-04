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
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"bq-caldav/core"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-vcard"
)

type FSBackend struct {
	create  func(p string) (io.WriteCloser, error)
	mkdir   func(p string) error
	delete  func(p string) error
	fsys    fs.FS
	uidmap  map[string]string
	pfcache map[string]*pfCacheData
	lock    *sync.Mutex
}

type pfCacheData struct {
	content_type   string
	content_length int64
	modified_time  time.Time
	etag           string
	uid_key        string
	start          time.Time
	until          time.Time
	unbounded      bool
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
	pfcache := make(map[string]*pfCacheData)
	var content_length int64
	var content_type string
	var uid_key string
	h := fnv.New32a()
	if e := fs.WalkDir(fsys, ".", func(q string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() || path.Base(q) == "props.xml" {
			return nil
		} else if f, e := fsys.Open(q); e != nil {
			return e
		} else if fi, e := de.Info(); e != nil {
			return e
		} else {
			h.Reset()
			content_length = 0
			br.Reset(io.TeeReader(f, h))
			for {
				if l, e := br.ReadSlice('\n'); e == nil {
					content_length += int64(len(l))
					if bytes.HasPrefix(l, []byte("BEGIN:VCALENDAR")) {
						content_type = ical.MIMEType
					} else if bytes.HasPrefix(l, []byte("BEGIN:VCARD")) {
						content_type = vcard.MIMEType
					} else if !bytes.HasPrefix(l, []byte("UID:")) {
						continue
					} else if l = bytes.TrimSpace(l[4:]); true {
						uid_key = fmt.Sprintf("%s:%s", path.Dir(q), l)
						uidmap[uid_key] = "/" + q
						k, _ := io.Copy(io.Discard, br)
						content_length += k
						if content_type != "" {
							pfcache[q] = &pfCacheData{
								content_type:   content_type,
								content_length: content_length,
								modified_time:  fi.ModTime(),
								etag:           base32.StdEncoding.EncodeToString(h.Sum(nil))[:7],
								uid_key:        uid_key,
							}
						}
					}
				} else {
					return nil
				}
			}
		}
	}); e != nil {
		panic(e)
	}

	for k, v := range pfcache {
		if v.content_type != ical.MIMEType {
			continue
		} else if f, e := fsys.Open(k); e != nil {
			panic(e)
		} else if cal, e := ical.NewDecoder(f).Decode(); e != nil {
			panic(e)
		} else if md, e := core.ParseCalendarObjectResource(cal, time.UTC); e != nil {
			panic(e)
		} else if start, until, unbounded, e := core.GetStartUntilUnbounded(md); e != nil {
			panic(e)
		} else {
			v.start = start
			v.until = until
			v.unbounded = unbounded
		}
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
		fsys:    os.DirFS(location),
		uidmap:  uidmap,
		pfcache: pfcache,
		lock:    new(sync.Mutex),
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

	err = core.WebDAVerror(http.StatusNotFound, nil)
	if cache_data, ok := b.pfcache[p]; !ok {
		//
	} else if f, e := b.fsys.Open(p); e != nil {
		//
	} else if b, e := io.ReadAll(f); e != nil {
		//
	} else if e := core.IfMatchifNoneMatch(cache_data.etag, r.Header.Get("If-Match"), r.Header.Get("If-None-Match")); e != nil {
		err = e
	} else {
		content_type = cache_data.content_type
		body = b
		err = nil
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
	return buf.Bytes(), vcard.MIMEType
}

// DELETE
func (b *FSBackend) Delete(r *http.Request) (err error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	p := path.Clean(r.URL.Path)[1:]

	if cache_data, ok := b.pfcache[p]; !ok {
		return core.WebDAVerror(http.StatusNotFound, nil)
	} else if fi, e := fs.Stat(b.fsys, p); e != nil {
		return core.WebDAVerror(http.StatusNotFound, nil)
	} else if fi.IsDir() {
		return b.delete(p)
	} else if e := core.IfMatchifNoneMatch(cache_data.etag, r.Header.Get("If-Match"), r.Header.Get("If-None-Match")); e != nil {
		return err
	} else if e := b.delete(p); e != nil {
		return e
	} else {
		delete(b.uidmap, cache_data.uid_key)
		delete(b.pfcache, p)
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

	cache_data, cache_ok := b.pfcache[p]

	if cache_ok {
		if e := core.IfMatchifNoneMatch(cache_data.etag, r.Header.Get("If-Match"), r.Header.Get("If-None-Match")); e != nil {
			return nil, e
		}
	}

	// check additional caldav preconditions
	// https://datatracker.ietf.org/doc/html/rfc4791#section-5.3.2.1
	//
	buf := bytes.NewBuffer(nil)

	loc, err := core.GetLocationFromProp(collection_prop)
	if err != nil {
		return nil, err
	}
	// todo: rewrite floating times using loc ?

	if md, e := core.ParseCalendarObjectResource(cal, loc); e != nil {
		return nil, e
	} else if start, until, unbounded, e := core.GetStartUntilUnbounded(md); e != nil {
		return nil, e
	} else if e := core.CheckCalendarCompIsSupported(collection_prop, md.ComponentType); e != nil {
		return nil, e
	} else if uid, e := md.GetUID(); e != nil {
		return nil, e
	} else if uid_key := path.Dir(p) + ":" + uid; false {
		//
	} else if v, ok := b.uidmap[uid_key]; ok && v != r.URL.Path {
		return nil, &core.UidConflict{Scope: core.CalendarScope, Href: core.Href{Target: v}}
	} else if cache_ok && cache_data.uid_key != uid_key {
		return nil, &core.UidConflict{Scope: core.CalendarScope, Href: core.Href{Target: r.URL.Path}}
	} else if e := ical.NewEncoder(buf).Encode(cal); e != nil {
		return nil, core.WebDAVerror(http.StatusInternalServerError, nil)
	} else if e := core.CheckMaxResourceSize(collection_prop, uint64(buf.Len())); e != nil {
		return nil, e
	} else if e := core.CheckOtherCalendarPreconditions(collection_prop, md); e != nil {
		return nil, e
	} else {
		h := fnv.New32a()
		h.Write(buf.Bytes())
		b.pfcache[p] = &pfCacheData{
			content_type:   ical.MIMEType,
			content_length: int64(buf.Len()),
			modified_time:  time.Now(),
			etag:           base32.StdEncoding.EncodeToString(h.Sum(nil))[:7],
			uid_key:        uid_key,
			start:          start,
			until:          until,
			unbounded:      unbounded,
		}
		b.uidmap[path.Dir(p)+":"+uid] = r.URL.Path
	}

	return buf, nil
}

func (b *FSBackend) checkAddressObject(r *http.Request, p string, card vcard.Card) (io.Reader, error) {
	// if `if-match` or `if-none-match` fails return 412 precondition failed
	// https://datatracker.ietf.org/doc/html/rfc7232
	//
	// don't bother checking the error; etag == "" if the file does not exist

	cache_data, cache_ok := b.pfcache[p]

	if cache_ok {
		if e := core.IfMatchifNoneMatch(cache_data.etag, r.Header.Get("If-Match"), r.Header.Get("If-None-Match")); e != nil {
			return nil, e
		}
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
	} else if uid_key := path.Dir(p) + ":" + uid; false {
		//
	} else if v, ok := b.uidmap[uid_key]; ok && v != r.URL.Path {
		return nil, &core.UidConflict{Scope: core.AddressbookScope, Href: core.Href{Target: v}}
	} else if cache_ok && cache_data.uid_key != uid_key {
		return nil, &core.UidConflict{Scope: core.AddressbookScope, Href: core.Href{Target: r.URL.Path}}
	} else if e := vcard.NewEncoder(buf).Encode(card); e != nil {
		return nil, core.WebDAVerror(http.StatusInternalServerError, nil)
	} else if e := core.CheckMaxResourceSize(collection_prop, uint64(buf.Len())); e != nil {
		return nil, e
	} else {
		h := fnv.New32a()
		h.Write(buf.Bytes())
		b.pfcache[p] = &pfCacheData{
			content_type:   vcard.MIMEType,
			content_length: int64(buf.Len()),
			modified_time:  time.Now(),
			etag:           base32.StdEncoding.EncodeToString(h.Sum(nil))[:7],
			uid_key:        uid_key,
		}
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
	} else if isDir := stat.IsDir(); !isDir || depth == 0 {
		if resp, e := b.propFindResource(p, isDir, pf); e != nil {
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
		} else if resp, e := b.propFindResource(q, de.IsDir(), pf); e != nil {
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

func (b *FSBackend) propFindResource(p string, isDir bool, pf *core.PropFind) (resp *core.Response, err error) {
	var props_Found []core.Any
	if isDir {
		props_Found, err = b.propFindDir(p)
	} else {
		props_Found, err = b.propFindFile(p)
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

func (b *FSBackend) propFindFile(p string) (props_Found []core.Any, err error) {
	cache_data, ok := b.pfcache[p]
	if !ok {
		return nil, &notFound{}
	}
	props_Found = core.DefaultPropsFile(cache_data.content_type, cache_data.content_length, cache_data.modified_time, cache_data.etag)
	return
}

type quickQuery struct {
	start time.Time
	end   time.Time
}

// small error chance if the client queries for different components
// with different time ranges.
func getQuickQuery(query *core.Query) *quickQuery {
	var start, end time.Time
	for _, cf := range query.CalendarFilter.CompFilter.CompFilters {
		if cf.TimeRange == nil {
			continue
		}
		cf_start, cf_end := cf.TimeRange.GetTimes()

		if start.IsZero() {
			start = cf_start
		} else if cf_start.Before(start) {
			start = cf_start
		}

		if end.IsZero() {
			end = cf_end
		} else if end.Before(cf_end) {
			cf_end = end
		}
	}
	return &quickQuery{start, end}
}

// REPORT calendar-query
func (b *FSBackend) CalendarQuery(r *http.Request, query *core.Query, depth byte) (ms *core.MultiStatus, err error) {
	p := path.Clean(r.URL.Path)[1:]
	if p == "" {
		p = "."
	}

	ms = &core.MultiStatus{}

	var query_root bool
	if path_comps := strings.Split(p, "/"); false {
	} else if path_comps[0] != "calendars" {
		err = core.WebDAVerror(http.StatusBadRequest, nil)
		return
	} else if len(path_comps) == 1 {
		if depth == 0 {
			// empty multistatus
			return
		} else {
			query_root = true
		}
	} else if len(path_comps) == 2 {
		//
	} else if len(path_comps) > 2 {
		err = core.WebDAVerror(http.StatusMethodNotAllowed, nil)
		return
	}

	// depth is functionally infinite at this stage
	// proceed

	if e := core.CheckCalendarQueryFilterIsValid(query); e != nil {
		err = e
		return
	} else if cd, e := core.ParseCalendarData(query); e != nil {
		err = e
		return
	} else {
		query.CalendarData = cd
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	qq := getQuickQuery(query)

	resps := make([]core.Response, 0, 128)
	if !query_root {
		resps, err = b.queryCalendarCollection(p, query, qq, resps)
		ms.Responses = resps
		return
	} else {
		// query_root
		if des, e := fs.ReadDir(b.fsys, p); e != nil {
			// could not read, so empty response
			return
		} else {
			for _, de := range des {
				if !de.IsDir() {
					continue
				} else if new_resps, e := b.queryCalendarCollection(path.Join(p, de.Name()), query, qq, resps); e != nil {
					err = e
					return
				} else {
					resps = new_resps
				}
			}
		}
		ms.Responses = resps
		return
	}
}

func (b *FSBackend) queryCalendarCollection(q string, query *core.Query, qq *quickQuery, resps []core.Response) (new_resps []core.Response, err error) {
	if des, e := fs.ReadDir(b.fsys, q); e != nil {
		// could not read, so empty response
		return
	} else {
		for _, de := range des {
			p := path.Join(q, de.Name())
			if de.IsDir() {
				continue
			} else if cache_data, ok := b.pfcache[p]; !ok {
				continue
			} else if !qq.end.IsZero() && (cache_data.start.After(qq.end) || cache_data.start.Equal(qq.end)) {
				continue
			} else if cache_data.unbounded {
				//
			} else if !qq.start.IsZero() && cache_data.until.Before(qq.start) {
				continue
			}

			if r, m, e := b.queryFile(p, query); !m || errors.Is(e, &notFound{}) {
				continue
			} else if e != nil {
				err = e
				return
			} else {
				resps = append(resps, *r)
			}
		}
	}
	new_resps = resps
	return
}

func (b *FSBackend) AddressbookQuery(r *http.Request, query *core.Query, depth byte) (ms *core.MultiStatus, err error) {
	p := path.Clean(r.URL.Path)[1:]
	if p == "" {
		p = "."
	}

	if path_comps := strings.Split(p, "/"); false {
	} else if path_comps[0] != "addressbook" {
		err = core.WebDAVerror(http.StatusBadRequest, nil)
		return
	} else if len(path_comps) == 1 {
		if depth == 0 {
			// empty multistatus
			return
		}
	} else if len(path_comps) == 2 {
		//
	} else if len(path_comps) > 2 {
		err = core.WebDAVerror(http.StatusMethodNotAllowed, nil)
		return
	}

	if query.AddressbookFilter == nil {
		err = core.WebDAVerror(http.StatusBadRequest, nil)
		return
	} else if ad, e := core.ParseAddressData(query); e != nil {
		err = e
		return
	} else {
		query.AddressData = ad
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	ms = &core.MultiStatus{}

	resps := make([]core.Response, 0, 128)
	err = fs.WalkDir(b.fsys, p, func(q string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return nil
		} else if resp, match, e := b.queryFile(q, query); e != nil || !match {
			if !errors.Is(e, &notFound{}) {
				return e
			}
			return nil
		} else {
			resps = append(resps, *resp)
		}
		return nil
	})

	// only relevant for addressbook-query
	if query.NResults != 0 && query.NResults < query.NSeen {
		// add a response
		resps = append(resps, core.InsufficientStorage(r.URL.Path))
	}

	ms.Responses = resps
	return
}

func (b *FSBackend) queryFile(p string, query *core.Query) (resp *core.Response, match bool, err error) {
	var props_Found []core.Any
	if pf, e := b.propFindFile(p); e != nil {
		err = e
		return
	} else {
		props_Found = pf
	}

	// not asking for any data?
	// skip the full query
	if query.CalendarData == nil && query.AddressData == nil {
		goto jump
	}

	switch query.Scope() {
	case core.CalendarScope:
		// now check if the file matches the query
		if file, e := b.fsys.Open(p); e != nil {
			err = &notFound{}
			return
		} else if cal, e := ical.NewDecoder(file).Decode(); e != nil {
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
		} else if a, e := core.CalendarData(cal, query.CalendarData, time.UTC); e != nil {
			// internal server error or webdav not-implemented
			err = e
			return
		} else if a != nil {
			props_Found = append(props_Found, *a)
		}
	case core.AddressbookScope:
		if file, e := b.fsys.Open(p); e != nil {
			err = &notFound{}
			return
		} else if card, e := vcard.NewDecoder(file).Decode(); e != nil {
			err = e
			return
		} else if m := core.MatchCardWithQuery(card, query); !m {
			// did not match
			err = &notFound{}
			return
		} else if a, e := core.AddressData(card, query.AddressData); e != nil {
			err = e
			return
		} else if a != nil {
			props_Found = append(props_Found, *a)
		}
	default:
		panic("unknown scope")
	}

jump:
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
		} else if ad, e := core.ParseAddressData(multiget); e != nil {
			err = e
			return
		} else {
			multiget.AddressData = ad
		}
	}

	var resps []core.Response

	if fi, e := fs.Stat(b.fsys, p); e != nil {
		return
	} else if !fi.IsDir() {
		if resp, e := b.multigetFile(p, multiget); e != nil {
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
		} else if resp, e := b.multigetFile(q, multiget); e != nil {
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

func (b *FSBackend) multigetFile(p string, multiget *core.Multiget) (resp *core.Response, err error) {
	for _, href := range multiget.Hrefs {
		if path.Clean(href.Target)[1:] == p {
			goto jump
		}
	}
	return nil, &notFound{}
jump:
	var props_Found []core.Any
	if pf, e := b.propFindFile(p); e != nil {
		err = e
		return
	} else {
		props_Found = pf
	}

	switch multiget.Scope() {
	case core.CalendarScope:
		// now write calendar-data
		if file, e := b.fsys.Open(p); e != nil {
			err = &notFound{}
			return
		} else if cal, e := ical.NewDecoder(file).Decode(); e != nil {
			err = &notFound{}
			return
		} else if a, e := core.CalendarData(cal, multiget.CalendarData, time.UTC); e != nil {
			err = e
			return
		} else if a != nil {
			props_Found = append(props_Found, *a)
		}
	case core.AddressbookScope:
		if file, e := b.fsys.Open(p); e != nil {
			err = &notFound{}
			return
		} else if card, e := vcard.NewDecoder(file).Decode(); e != nil {
			err = &notFound{}
			return
		} else if a, e := core.AddressData(card, multiget.AddressData); e != nil {
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

// FBQuery
func (b *FSBackend) FBQuery(r *http.Request, fbquery *core.FBQuery, depth byte) (resp []byte, err error) {
	// with this implementation, REPORT must be targeting /calendars/ or /calendars/X
	p := path.Clean(r.URL.Path[1:])
	if elements := strings.Split(p, "/"); len(elements) > 2 {
		err = core.WebDAVerror(http.StatusForbidden, nil)
	} else if elements == nil || elements[0] != "calendars" {
		err = core.WebDAVerror(http.StatusMethodNotAllowed, nil)
	} else if fi, e := fs.Stat(b.fsys, p); e != nil {
		err = core.WebDAVerror(http.StatusNotFound, nil)
	} else if !fi.IsDir() {
		err = core.WebDAVerror(http.StatusForbidden, nil)
	}

	start, end := fbquery.TimeRange.GetTimes()

	periods := make([]core.Period, 0, 128)
	if e := fs.WalkDir(b.fsys, p, func(q string, de fs.DirEntry, err error) error {
		if cache_data, ok := b.pfcache[q]; !ok {
			return nil
		} else if cache_data.unbounded {
			//
		} else if cache_data.until.Before(start) {
			return nil
		} else if cache_data.start.After(end) || cache_data.start.Equal(end) {
			return nil
		} else {
			//
		}

		if err != nil || de.IsDir() {
			return nil
		} else if file, e := b.fsys.Open(q); e != nil {
			return nil
		} else if cal, e := ical.NewDecoder(file).Decode(); e != nil {
			return file.Close()
		} else if e := file.Close(); e != nil {
			return e
		} else if ps, e := core.FBQueryObject(cal, time.UTC, fbquery, periods); e != nil {
			return e
		} else {
			periods = ps
		}
		return nil
	}); e != nil {
		err = e
		return
	}

	cal := core.CoalesceToFreeBusy(periods, fbquery)
	buf := bytes.NewBuffer(nil)
	if e := ical.NewEncoder(buf).Encode(cal); e != nil {
		return nil, e
	} else {
		return buf.Bytes(), nil
	}
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
			allow = []string{http.MethodOptions, "PROPFIND", "REPORT"}
		case 2: // path targets /calendars/X
			allow = []string{http.MethodOptions, "PROPFIND", "REPORT", "PROPPATCH", "MKCOL", "MKCALENDAR", "DELETE"}
		case 3: // path targets /calendars/X/Y
			allow = []string{http.MethodOptions, "PROPFIND", "DELETE", "PUT", "GET", "HEAD"}
		}
	} else if components[0] == "addressbook" {
		caps = []string{"1", "3", "addressbook", "extended-mkcol"}
		switch len(components) {
		case 1: // path targets /addressbook
			allow = []string{http.MethodOptions, "PROPFIND", "REPORT"}
		case 2: // path targets /addressbook/X
			allow = []string{http.MethodOptions, "PROPFIND", "REPORT", "PROPPATCH", "MKCOL", "DELETE"}
		case 3: // path targets /addressbook/X/Y
			allow = []string{http.MethodOptions, "PROPFIND", "DELETE", "PUT", "GET", "HEAD"}
		}
	}
	return
}
