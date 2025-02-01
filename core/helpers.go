package core

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-vcard"
)

var (
	statusOK                                             = statusHelper(http.StatusOK)
	statusNotFound                                       = statusHelper(http.StatusNotFound)
	statusFailedDependency                               = statusHelper(http.StatusFailedDependency)
	statusForbidden                                      = statusHelper(http.StatusForbidden)
	statusBadRequest                                     = statusHelper(http.StatusBadRequest)
	principalURL, currentUserPrincipal, principalAddress = newPrincipalURL("/")
	defaultSupportedAddressData                          = supportedAddressDataHelper("3.0", "4.0")
	defaultSupportedCalendarComponentSet                 = supportedCalendarComponentSetHelper("VEVENT", "VTODO", "VJOURNAL", "VFREEBUSY")
	defaultCalendarHomeSet                               = newCalendarHomeSet("/calendars/")
	defaultAddressbookHomeSet                            = newAddressbookHomeSet("/addressbook/")
	collectionResourceType                               = newResourceType(collectionTypeName)
	calendarResourceType                                 = newResourceType(collectionTypeName, calendarTypeName)
	addressbookResourceType                              = newResourceType(collectionTypeName, addressbookTypeName)
)

func newCalendarHomeSet(href string) Any {
	if b, e := xml.Marshal(Href{Target: href}); e != nil {
		panic(e)
	} else {
		return Any{
			XMLName: calendarHomeSetName,
			Content: b,
		}
	}
}

func newAddressbookHomeSet(href string) Any {
	if b, e := xml.Marshal(Href{Target: href}); e != nil {
		panic(e)
	} else {
		return Any{
			XMLName: addressbookHomeSetName,
			Content: b,
		}
	}
}

func newPrincipalURL(href string) (principalURL Any, currentUserPrincipal Any, principalAddress Any) {
	if b, e := xml.Marshal(Href{Target: href}); e != nil {
		panic(e)
	} else if b_medotvcf, e := xml.Marshal(Href{Target: path.Join(href, "me.vcf")}); e != nil {
		panic(e)
	} else {
		return Any{
				XMLName: principalURLName,
				Content: b,
			}, Any{
				XMLName: currentUserPrincipalName,
				Content: b,
			}, Any{
				XMLName: principalAddressName,
				Content: b_medotvcf,
			}
	}
}

func supportedCalendarComponentSetHelper(types ...string) Any {
	comps := make([]Any, len(types))
	for k, t := range types {
		comps[k] = Any{
			XMLName: compName,
			Attr: []xml.Attr{
				{
					Name:  xml.Name{Local: "name"},
					Value: t,
				},
			},
		}
	}
	if b, e := xml.Marshal(comps); e != nil {
		panic(e)
	} else {
		return Any{
			XMLName: supportedCalendarComponentSetName,
			Content: b,
		}
	}
}

func supportedAddressDataHelper(versions ...string) Any {
	data_types := make([]Any, len(versions))
	for k, v := range versions {
		data_types[k] = Any{
			XMLName: addressDataTypeName,
			Attr: []xml.Attr{
				{
					Name:  xml.Name{Local: "content-type"},
					Value: "text/vcard",
				}, {
					Name:  xml.Name{Local: "version"},
					Value: v,
				},
			},
		}
	}
	if b, e := xml.Marshal(data_types); e != nil {
		panic(e)
	} else {
		return Any{
			XMLName: supportedAddressDataName,
			Content: b,
		}
	}
}

func newResourceType(names ...xml.Name) Any {
	buf := bytes.NewBuffer(nil)
	for _, name := range names {
		buf.WriteString(fmt.Sprintf("<%s xmlns=\"%s\"/>", name.Local, name.Space))
	}
	return Any{
		XMLName: resourceTypeName,
		Content: buf.Bytes(),
	}
}

func statusHelper(code int) status {
	return status{Text: fmt.Sprintf("HTTP/1.1 %v %v", code, http.StatusText(code))}
}

func emptyCalendarData() *Any {
	return &Any{
		XMLName: calendarDataName,
	}
}

func supportedReportSetHelper(names ...xml.Name) *Any {
	srs := make([]supportedReport, len(names))

	for k, n := range names {
		srs[k] = supportedReport{
			Report: report{
				Value: Any{
					XMLName: n,
				},
			},
		}
	}

	a := &Any{}
	if b, e := xml.Marshal(supportedReportSet{
		SupportedReports: srs,
	}); e != nil {
		panic(e)
	} else if e := xml.Unmarshal(b, a); e != nil {
		panic(e)
	} else {
		return a
	}
}

func (s Scope) supportedReportSet() *Any {
	switch s {
	case CalendarScope:
		return supportedReportSetHelper(calendarQueryName, calendarMultiGetName)
	case AddressbookScope:
		return supportedReportSetHelper(addressbookQueryName, addressbookMultiGetName)
	default:
		return nil
	}
}

func isContentXML(h http.Header) (bool, error) {
	if t, _, e := mime.ParseMediaType(h.Get("Content-Type")); e == nil {
		return t == "application/xml" || t == "text/xml", nil
	} else if e.Error() == "mime: no media type" {
		return false, nil
	} else {
		return false, &webDAVerror{Code: http.StatusUnsupportedMediaType}
	}
}

func wrapError(condition xml.Name, content []byte) *davError {
	return &davError{
		Conditions: []Any{{XMLName: condition, Content: content}},
	}
}

// propfind

func allprop_filter(include []Any, found []Any) (prop_OK []Any, prop_NotFound []Any) {
	prop_OK = make([]Any, 0, len(allpropInclusions)+len(include))
outer1:
	for _, prop := range found {
		for _, n := range allpropInclusions {
			if prop.XMLName == n {
				prop_OK = append(prop_OK, prop)
				continue outer1
			}
		}
		// do nothing
	}
outer2:
	for _, iprop := range include {
		for _, prop := range found {
			if iprop.XMLName == prop.XMLName {
				prop_OK = append(prop_OK, prop)
				continue outer2
			}
		}
		prop_NotFound = append(prop_NotFound, iprop)
	}
	return
}

func match(req []Any, found []Any) (prop_OK []Any, prop_NotFound []Any) {
	prop_OK = make([]Any, 0, len(found))
	prop_NotFound = make([]Any, 0, len(req))
outer:
	for _, reqp := range req {
		for _, reqf := range found {
			if reqp.XMLName == reqf.XMLName {
				prop_OK = append(prop_OK, reqf)
				continue outer
			}
		}
		prop_NotFound = append(prop_NotFound, reqp)
	}
	return
}

func CleanProps(scope Scope, props_Found []Any, propName *struct{}, include *Include, allProp *struct{}, reqProp *Prop) (propstats []PropStat) {
	props_Found = append(props_Found, currentUserPrincipal, principalURL)
	if a := scope.supportedReportSet(); a != nil {
		props_Found = append(props_Found, *a)
	}

	var props_OK []Any
	var props_NotFound []Any
	switch {
	case propName != nil:
		for k, v := range props_Found {
			props_Found[k] = Any{XMLName: v.XMLName}
		}
		props_OK = props_Found
	case allProp != nil:
		var inclusions []Any
		if include != nil {
			inclusions = include.Inclusions
		}
		props_OK, props_NotFound = allprop_filter(inclusions, props_Found)
	default:
		props_OK, props_NotFound = match(reqProp.Props, props_Found)
	}

	propstats = make([]PropStat, 0, 2)
	if len(props_OK) != 0 {
		propstats = append(propstats, PropStat{
			Prop: Prop{
				Props: props_OK,
			},
			Status: statusOK,
		})
	}
	if len(props_NotFound) != 0 {
		propstats = append(propstats, PropStat{
			Prop: Prop{
				Props: props_NotFound,
			},
			Status: statusNotFound,
		})
	}
	return propstats
}

func DefaultPropsFile(content_type string, content_length int64, modified_time time.Time, etag string) []Any {
	return []Any{
		Any{
			XMLName: resourceTypeName,
			Content: nil,
		},
		Any{
			XMLName: getContentTypeName,
			Content: []byte(content_type),
		},
		Any{
			XMLName: getContentLengthName,
			Content: []byte(fmt.Sprintf("%d", content_length)),
		},
		Any{
			XMLName: getLastModifiedName,
			Content: []byte(modified_time.Format("Mon, 02 Jan 2006 15:04:05 MST")),
		},
		Any{
			XMLName: getETagName,
			Content: []byte(strconv.Quote(etag)),
		},
	}
}

func DefaultPropsRoot() []Any {
	return []Any{
		collectionResourceType,
		defaultCalendarHomeSet,
		defaultAddressbookHomeSet,
		principalAddress,
	}
}

func DefaultPropsHomeSet() []Any {
	return []Any{
		collectionResourceType,
	}
}

func MarshalPropsCalendarCollection(custom *Prop) (props_Found []Any) {
	props_Found = []Any{
		calendarResourceType,
	}
	for _, q := range custom.Props {
		if q.XMLName == resourceTypeName {
			continue
		}
		props_Found = append(props_Found, q)
	}
	return
}

func MarshalPropsAddressbookCollection(custom *Prop) (props_Found []Any) {
	props_Found = []Any{
		addressbookResourceType,
		defaultSupportedAddressData,
	}
	for _, q := range custom.Props {
		if q.XMLName == resourceTypeName || q.XMLName == supportedAddressDataName {
			continue
		}
		props_Found = append(props_Found, q)
	}
	return
}

// etag
func matchETag(etag string, header_val string) (isSet bool, match bool, err error) {
	if header_val != "" && etag == "" {
		return true, false, nil
	} else if header_val == "" {
		return false, false, nil
	} else if header_val == "*" {
		return true, true, nil
	}
	for _, quote_et := range strings.Split(header_val, ", ") {
		if unquote_et, e := strconv.Unquote(quote_et); e != nil {
			err = e
			return
		} else if unquote_et == etag {
			return true, true, nil
		}
	}
	return true, false, nil
}

func IfMatchifNoneMatch(etag string, ifmatch string, ifnonematch string) (err error) {
	// If-Match
	if isSet, match, e := matchETag(etag, ifmatch); e != nil {
		err = &webDAVerror{
			Code: http.StatusBadRequest,
		}
	} else if !isSet {
		// continue
	} else if !match {
		err = &webDAVerror{
			Code: http.StatusPreconditionFailed,
		}
	}
	if err != nil {
		return
	}

	// If-None-Match
	if isSet, match, e := matchETag(etag, ifnonematch); e != nil {
		err = &webDAVerror{
			Code: http.StatusBadRequest,
		}
	} else if !isSet {
		// continue
	} else if match {
		err = &webDAVerror{
			Code: http.StatusPreconditionFailed,
		}
	}
	return
}

// proppatch
func parsePropertyUpdate(pp *PropertyUpdate) (remove_props []Any, set_props []Any) {
	remove_props = make([]Any, 0, 8)
	set_props = make([]Any, 0, 8)

	for _, rset := range pp.Remove {
	mid1:
		for _, r := range rset.Props {
			for _, t := range remove_props {
				if t.XMLName == r.XMLName {
					continue mid1
				}
			}
			remove_props = append(remove_props, r)
		}
	}
	for _, sset := range pp.Set {
		for _, s := range sset.Props {
			for k, t := range set_props {
				if t.XMLName == s.XMLName {
					set_props[k] = s
				}
			}
			set_props = append(set_props, s)
		}
	}
	return
}

var protected_webdav = []xml.Name{resourceTypeName}
var protected_calendar = []xml.Name{supportedCalendarComponentSetName, supportedCalendarDataName, calendarMaxResourceSizeName, minDateTimeName, maxDateTimeName, maxInstancesName, maxAttendeesPerInstanceName, calendarSupportedCollationSetName}
var protected_addressbook = []xml.Name{supportedAddressDataName, addressbookMaxResourceSizeName, addressbookSupportedCollationSetName}

func isProtected(scope Scope, prop_name xml.Name) bool {
	for _, p := range protected_webdav {
		if p == prop_name {
			return true
		}
	}
	switch scope {
	case CalendarScope:
		for _, p := range protected_calendar {
			if p == prop_name {
				return true
			}
		}
	case AddressbookScope:
		for _, p := range protected_addressbook {
			if p == prop_name {
				return true
			}
		}
	}
	return false
}

func PropPatchHelper(scope Scope, current_prop *Prop, property_update *PropertyUpdate) (ms *MultiStatus, new_prop *Prop) {
	remove_props, set_props := parsePropertyUpdate(property_update)

	new_props := make([]Any, 0, len(current_prop.Props))

	status_OK := make([]Any, 0, len(current_prop.Props))
	status_Protected := make([]Any, 0, 1)
	status_BadRequest := make([]Any, 0, 1)

outer1:
	for _, val := range current_prop.Props {
		for _, remove := range remove_props {
			if val.XMLName != remove.XMLName {
				continue
			} else if isProtected(scope, remove.XMLName) {
				status_Protected = append(status_Protected, Any{XMLName: remove.XMLName})
			} else {
				status_OK = append(status_OK, Any{XMLName: remove.XMLName})
			}
			continue outer1
		}
		new_props = append(new_props, val)
	}

	status_NotFound := make([]Any, 0, 2)
outer2:
	for _, remove := range remove_props {
		for _, n := range status_OK {
			if n.XMLName == remove.XMLName {
				continue outer2
			}
		}
		for _, n := range status_Protected {
			if n.XMLName == remove.XMLName {
				continue outer2
			}
		}
		status_NotFound = append(status_NotFound, Any{XMLName: remove.XMLName})
	}

outer3:
	for _, set := range set_props {
		if isProtected(scope, set.XMLName) {
			status_Protected = append(status_Protected, Any{XMLName: set.XMLName})
			continue outer3
		} else if set.XMLName == calendarTimezoneName {
			if encoded, e := checkTimezoneInReq(set.Content); e != nil {
				status_BadRequest = append(status_BadRequest, Any{XMLName: set.XMLName})
				continue outer3
			} else {
				set.Content = encoded
			}
		}
		// not protected
		status_OK = append(status_OK, Any{XMLName: set.XMLName})
		for k, val := range new_props {
			if val.XMLName != set.XMLName {
				continue
			}
			new_props[k] = set
			continue outer3
		}
		new_props = append(new_props, set)
	}

	prop_stats := make([]PropStat, 0, 4)
	if len(status_NotFound) != 0 {
		prop_stats = append(prop_stats, PropStat{Prop: Prop{Props: status_NotFound}, Status: statusNotFound})
	}
	if len(status_Protected) != 0 {
		e := &davError{Conditions: []Any{{XMLName: xml.Name{Space: "DAV:", Local: "cannot-modify-protected-property"}}}}
		prop_stats = append(prop_stats, PropStat{Prop: Prop{Props: status_Protected}, Status: statusForbidden, Error: e})
	}
	if len(status_BadRequest) != 0 {
		e := &davError{Conditions: []Any{{XMLName: validCalendarDataName}}}
		prop_stats = append(prop_stats, PropStat{Prop: Prop{Props: status_BadRequest}, Status: statusBadRequest, Error: e})
	}
	if len(status_OK) != 0 {
		status := statusOK
		if len(prop_stats) != 0 {
			status = statusFailedDependency
		} else {
			// statusOK
			new_prop = &Prop{
				Props: filterProps(new_props),
			}
		}
		prop_stats = append(prop_stats, PropStat{
			Prop: Prop{
				Props: status_OK,
			},
			Status: status,
		})
	}

	resp := Response{
		PropStats: prop_stats,
	}
	ms = &MultiStatus{
		Responses: []Response{resp},
	}

	return
}

// multiget helper
func MarshalMultigetRespose(multiget *Multiget, resps []Response) *MultiStatus {
outer:
	for _, href := range multiget.Hrefs {
		for _, resp := range resps {
			if resp.Hrefs[0].Target == href.Target {
				continue outer
			}
		}
		resps = append(resps, Response{
			Hrefs:  []Href{href},
			Status: &statusNotFound,
		})
	}
	return &MultiStatus{
		Responses: resps,
	}
}

// put helper
func CheckCalendarDataSupportedAndValid(content_type_header string, request_body io.Reader) (cal *ical.Calendar, err error) {
	err = &webDAVerror{
		Code:      http.StatusForbidden,
		Condition: &supportedCalendarDataName,
	}

	if mt, _, e := mime.ParseMediaType(content_type_header); e != nil || mt != ical.MIMEType {
		return
	}

	err = &webDAVerror{
		Code:      http.StatusForbidden,
		Condition: &validCalendarDataName,
	}

	if c, e := ical.NewDecoder(request_body).Decode(); e != nil {
		return
	} else {
		cal = c
	}

	for _, child := range cal.Children {
		for _, subchild := range child.Children {
			switch subchild.Name {
			case ical.CompAlarm:
				if child.Name != ical.CompEvent && child.Name != ical.CompToDo {
					return
				} else if _, e := DoesAlarmIntersect(subchild, child, time.UTC, time.Now(), time.Time{}); e != nil {
					// check all alarms can be used
					return
				}
			case ical.CompTimezoneDaylight, ical.CompTimezoneStandard:
				if child.Name != ical.CompTimezone {
					return
				}
			}
		}
	}

	err = nil
	return
}

func CheckCalendarCompIsSupported(p *Prop, comp_type string) (err error) {
	err = &webDAVerror{
		Code: http.StatusInternalServerError,
	}
	var sccs Any
	for _, a := range p.Props {
		if a.XMLName == supportedCalendarComponentSetName {
			sccs = a
			goto jump
		}
	}
	return nil
jump:
	d := xml.NewDecoder(bytes.NewBuffer(sccs.Content))
	for {
		if tok, e := d.Token(); e != nil {
			if errors.Is(e, io.EOF) {
				break
			} else {
				return
			}
		} else if t, ok := tok.(xml.StartElement); ok {
			for _, attr := range t.Attr {
				if name, val := attr.Name.Local, attr.Value; name != "name" {
					continue
				} else if val == comp_type {
					err = nil
					return
				}
			}
		}
	}
	return &webDAVerror{
		Code:      http.StatusForbidden,
		Condition: &supportedCalendarComponentName,
	}
}

func CheckAddressDataSupportedAndValid(content_type_header string, request_body io.Reader) (card vcard.Card, err error) {
	if mt, _, e := mime.ParseMediaType(content_type_header); e != nil || mt != vcard.MIMEType {
		err = &webDAVerror{
			Code:      http.StatusForbidden,
			Condition: &supportedAddressDataName,
		}
	} else if c, e := vcard.NewDecoder(request_body).Decode(); e != nil {
		err = &webDAVerror{
			Code:      http.StatusForbidden,
			Condition: &validAddressDataName,
		}
	} else if v := c.Get(vcard.FieldFormattedName); v == nil {
		err = &webDAVerror{
			Code:      http.StatusForbidden,
			Condition: &validAddressDataName,
		}
	} else if v := c.Get(vcard.FieldUID); v == nil {
		err = &webDAVerror{
			Code:      http.StatusForbidden,
			Condition: &validAddressDataName,
		}
	} else {
		vcard.ToV4(c)
		card = c
	}
	return
}

func CheckMaxResourceSize(collection_prop *Prop, size uint64) error {
	// will panic if collection_prop is nil
	for _, a := range collection_prop.Props {
		if a.XMLName.Local == "max-resource-size" {
			if l, e := strconv.ParseUint(fmt.Sprintf("%s", a.Content), 10, 64); e != nil {
				return e
			} else if l < size {
				return &webDAVerror{
					Code:      http.StatusForbidden,
					Condition: &a.XMLName,
				}
			}
		}
	}
	return nil
}

func CheckOtherCalendarPreconditions(collection_prop *Prop, md *CalendarMetaData) error {
	for _, a := range collection_prop.Props {
		switch a.XMLName {
		case maxAttendeesPerInstanceName:
			if l, e := strconv.ParseUint(fmt.Sprintf("%s", a.Content), 10, 64); e != nil {
				return e
			} else {
				for _, c := range md.comps {
					if uint64(len(c.comp.Props.Values(ical.PropAttendee))) > l {
						return &webDAVerror{
							Code:      http.StatusForbidden,
							Condition: &a.XMLName,
						}
					}
				}
			}
		case maxInstancesName:
			if l, e := strconv.ParseUint(fmt.Sprintf("%s", a.Content), 10, 64); e != nil {
				return e
			} else {
				for _, c := range md.comps {
					if !rrule_count_instances(c.rrule, l) {
						return &webDAVerror{
							Code:      http.StatusForbidden,
							Condition: &a.XMLName,
						}
					}
				}
			}
		case maxDateTimeName:
			if t, e := time.ParseInLocation(dateWithUTCTimeFormat, fmt.Sprintf("%s", a.Content), time.UTC); e != nil {
				return e
			} else {
				for _, c := range md.comps {
					if c.Intersect(t, time.Time{}) {
						return &webDAVerror{
							Code:      http.StatusForbidden,
							Condition: &a.XMLName,
						}
					}
				}
			}
		case minDateTimeName:
			if t, e := time.ParseInLocation(dateWithUTCTimeFormat, fmt.Sprintf("%s", a.Content), time.UTC); e != nil {
				return e
			} else {
				for _, c := range md.comps {
					if c.Intersect(time.Time{}, t) {
						return &webDAVerror{
							Code:      http.StatusForbidden,
							Condition: &a.XMLName,
						}
					}
				}
			}
		}
	}
	return nil
}

func GetLocationFromProp(prop *Prop) (loc *time.Location, err error) {
	for _, p := range prop.Props {
		if p.XMLName != calendarTimezoneName {
			continue
		}
		err = fmt.Errorf("invalid timezone content")
		br := bytes.NewReader(p.Content)
		d := xml.NewDecoder(br)
		if t, e := d.Token(); e != nil {
			//
		} else if cd, ok := t.(xml.CharData); !ok {
			//
		} else if br.Reset(cd); false {
			//
		} else if tz_cal, e := ical.NewDecoder(br).Decode(); e != nil || len(tz_cal.Children) != 1 {
			//
		} else if tz_comp := tz_cal.Children[0]; tz_comp.Name != ical.CompTimezone {
			//
		} else if tz_id_prop := tz_comp.Props.Get(ical.PropTimezoneID); tz_id_prop == nil {
			//
		} else if l, e := time.LoadLocation(tz_id_prop.Value); e != nil {
			err = e
		} else {
			loc = l
			err = nil
		}
		return
	}
	return
}

// used in CheckMkColReq and in PropFind
func checkTimezoneInReq(content []byte) (encoded []byte, err error) {
	err = fmt.Errorf("invalid timezone content")
	br := bytes.NewReader(content)
	d := xml.NewDecoder(br)
	if t, e := d.Token(); e != nil {
		//
	} else if cd, ok := t.(xml.CharData); !ok {
		//
	} else if br.Reset(cd); false {
		//
	} else if tz_cal, e := ical.NewDecoder(br).Decode(); e != nil || len(tz_cal.Children) != 1 {
		//
	} else if tz_comp := tz_cal.Children[0]; tz_comp.Name != ical.CompTimezone {
		//
	} else if tz_id_prop := tz_comp.Props.Get(ical.PropTimezoneID); tz_id_prop == nil {
		//
	} else if _, e := time.LoadLocation(tz_id_prop.Value); e != nil {
		err = e
	} else if buf, esc := bytes.NewBuffer(nil), bytes.NewBuffer(nil); false {
		//
	} else if e := ical.NewEncoder(buf).Encode(tz_cal); e != nil {
		err = e
	} else if e := xml.EscapeText(esc, buf.Bytes()); e != nil {
		err = e
	} else {
		encoded = esc.Bytes()
		err = nil
	}
	return
}

func CheckMkColReq(scope Scope, prop_req []Prop) (resp []PropStat, prop_write Prop, err error) {
	new_props := make([]Any, 0, 16)
	bad_props := make([]PropStat, 0, 4)
	write_props := make([]Any, 0, 16)
	for _, prop := range prop_req {
		for _, a := range prop.Props {
			switch a.XMLName {
			case maxDateTimeName, minDateTimeName:
				if _, e := time.ParseInLocation(dateWithUTCTimeFormat, fmt.Sprintf("%s", a.Content), time.UTC); e != nil {
					bad_props = append(bad_props, PropStat{
						Prop: Prop{
							Props: []Any{{
								XMLName: a.XMLName,
							}},
						},
						Status: statusBadRequest,
					})
				} else {
					new_props = append(new_props, Any{XMLName: a.XMLName})
					write_props = append(write_props, a)
				}
			case calendarMaxResourceSizeName, addressbookMaxResourceSizeName, maxInstancesName, maxAttendeesPerInstanceName:
				if l, e := strconv.ParseUint(fmt.Sprintf("%s", a.Content), 10, 64); e != nil || l == 0 {
					bad_props = append(bad_props, PropStat{
						Prop: Prop{
							Props: []Any{{
								XMLName: a.XMLName,
							}},
						},
						Status: statusBadRequest,
					})
				} else {
					new_props = append(new_props, Any{XMLName: a.XMLName})
					write_props = append(write_props, a)
				}
			case calendarTimezoneName:
				if encoded, e := checkTimezoneInReq(a.Content); e != nil {
					bad_props = append(bad_props, PropStat{
						Prop: Prop{
							Props: []Any{{
								XMLName: a.XMLName,
							}},
						},
						Status: statusBadRequest,
					})
				} else {
					a.Content = encoded
					new_props = append(new_props, Any{XMLName: a.XMLName})
					write_props = append(write_props, a)
				}
			case resourceTypeName:
				var check int
				d := xml.NewDecoder(bytes.NewReader(a.Content))
				for {
					if tok, e := d.Token(); errors.Is(e, io.EOF) {
						break
					} else if t, ok := tok.(xml.StartElement); ok {
						switch scope {
						case CalendarScope:
							if t.Name == calendarTypeName || t.Name == collectionTypeName {
								check++
							}
						case AddressbookScope:
							if t.Name == addressbookTypeName || t.Name == collectionTypeName {
								check++
							}
						}
					}
				}
				if check != 2 {
					bad_props = append(bad_props, PropStat{
						Prop: Prop{
							Props: []Any{{
								XMLName: resourceTypeName,
							}},
						},
						Status: statusForbidden,
						Error:  wrapError(validResourceTypeName, nil),
					})
				} else {
					new_props = append(new_props, Any{XMLName: a.XMLName})
				}
			case supportedCalendarComponentSetName:
				if scope != CalendarScope {
					bad_props = append(bad_props, PropStat{
						Prop: Prop{
							Props: []Any{{
								XMLName: a.XMLName,
							}},
						},
						Status:              statusForbidden,
						ResponseDescription: "Unsupported property for non-calendar collections",
					})
					continue
				}
				var check bool = true
				d := xml.NewDecoder(bytes.NewBuffer(a.Content))
				for {
					if tok, e := d.Token(); e != nil {
						if errors.Is(e, io.EOF) {
							break
						} else {
							err = &webDAVerror{
								Code: http.StatusBadRequest,
							}
							return
						}
					} else if t, ok := tok.(xml.StartElement); ok {
						for _, attr := range t.Attr {
							if name, val := attr.Name.Local, attr.Value; name != "name" {
								continue
							} else if val != ical.CompEvent && val != ical.CompJournal && val != ical.CompToDo && val != ical.CompFreeBusy {
								check = false
								break
							}
						}
					}
				}
				if !check {
					bad_props = append(bad_props, PropStat{
						Prop: Prop{
							Props: []Any{{
								XMLName: a.XMLName,
							}},
						},
						Status:              statusForbidden,
						ResponseDescription: "only VEVENT, VTODO, VJOURNAL, VFREEBUSY collections are supported",
					})
				} else {
					write_props = append(write_props, a)
					new_props = append(new_props, Any{XMLName: a.XMLName})
				}
			case supportedAddressDataName:
				if scope != AddressbookScope {
					bad_props = append(bad_props, PropStat{
						Prop: Prop{
							Props: []Any{{
								XMLName: a.XMLName,
							}},
						},
						Status:              statusForbidden,
						ResponseDescription: "Unsupported property for non-addressbook collections",
					})
					continue
				}
				var check bool = true
				d := xml.NewDecoder(bytes.NewBuffer(a.Content))
				for {
					if tok, e := d.Token(); e != nil {
						if errors.Is(e, io.EOF) {
							break
						} else {
							err = &webDAVerror{
								Code: http.StatusBadRequest,
							}
							return
						}
					} else if t, ok := tok.(xml.StartElement); ok {
						for _, attr := range t.Attr {
							if name, val := attr.Name.Local, attr.Value; name != "version" && name != "content-type" {
								continue
							} else if name == "version" && val != "4.0" && val != "3.0" {
								check = false
								break
							} else if name == "content-type" && val != vcard.MIMEType {
								check = false
								break
							}
						}
					}
				}
				if !check {
					bad_props = append(bad_props, PropStat{
						Prop: Prop{
							Props: []Any{{
								XMLName: a.XMLName,
							}},
						},
						Status:              statusForbidden,
						ResponseDescription: "content-type must be \"text/vcard\" with version \"3.0\" or \"4.0\"",
					})
				} else {
					new_props = append(new_props, Any{XMLName: a.XMLName})
				}
			default:
				write_props = append(write_props, a)
				new_props = append(new_props, Any{XMLName: a.XMLName})
			}
		}
	}
	if len(bad_props) != 0 {
		resp = append(bad_props, PropStat{
			Prop: Prop{
				Props: new_props,
			},
			Status: statusFailedDependency,
		})
		return
	}
	// todo: remove this once all components are supported;
	// currently missing only timezone, (and alarm)
	if scope == CalendarScope {
		for _, w := range write_props {
			if w.XMLName == supportedCalendarComponentSetName {
				goto jump
			}
		}
		write_props = append(write_props, defaultSupportedCalendarComponentSet)
	}
jump:
	prop_write = Prop{
		Props: write_props,
	}
	return
}

func filterProps(new_props []Any) (filtered_props []Any) {
	filtered_props = make([]Any, 0, len(new_props))
	for _, prop := range new_props {
		switch prop.XMLName {
		case resourceTypeName, supportedCalendarComponentSetName, supportedAddressDataName:
			continue
		default:
			filtered_props = append(filtered_props, prop)
		}
	}
	return
}

func (m *Multiget) Scope() Scope {
	switch m.XMLName {
	case calendarMultiGetName:
		return CalendarScope
	case addressbookMultiGetName:
		return AddressbookScope
	default:
		return 0
	}
}

func (q *Query) Scope() Scope {
	switch q.XMLName {
	case calendarQueryName:
		return CalendarScope
	case addressbookQueryName:
		return AddressbookScope
	default:
		return 0
	}
}
