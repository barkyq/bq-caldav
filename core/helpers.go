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
	principalURL, currentUserPrincipal, principalAddress = newPrincipalURL("/")
	defaultSupportedCalendarComponentSet                 = supportedCalendarComponentSetHelper("VEVENT")
	defaultSupportedAddressData                          = supportedAddressDataHelper("3.0", "4.0")
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

// String method for Scope to provide a human-readable representation
func (s Scope) SupportedReportSet() *Any {
	switch s {
	case CalendarScope:
		return supportedReportSetHelper(calendarQueryName, calendarMultiGetName)
	case AddressbookScope:
		return supportedReportSetHelper(addressbookQueryName, addressbookMultiGetName)
	case CalendarScope | AddressbookScope:
		return supportedReportSetHelper(calendarQueryName, calendarMultiGetName, addressbookQueryName, addressbookMultiGetName)
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

func wrapError(condition xml.Name) *davError {
	return &davError{
		Conditions: []Any{{XMLName: condition}},
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
	if a := scope.SupportedReportSet(); a != nil {
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
		defaultSupportedCalendarComponentSet,
	}
	for _, q := range custom.Props {
		if q.XMLName == resourceTypeName || q.XMLName == supportedCalendarComponentSetName {
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

// comp filter

func MatchCalendarWithQuery(cal *ical.Calendar, query *Query) (bool, error) {
	if query.CalendarFilter == nil {
		return false, fmt.Errorf("query is unset")
	} else if query.CalendarFilter.CompFilter.Name != cal.Component.Name {
		return false, nil
	}

	return matchCompFilterWithComp(query.CalendarFilter.CompFilter, cal.Component)
}

func matchCompFilterWithComp(cf compFilter, comp *ical.Component) (match bool, err error) {
	switch {
	case cf.TimeRange != nil:
		if comp.Name != ical.CompEvent {
			// time range only implemented on
			// event components
			return false, &webDAVerror{
				Code: http.StatusNotImplemented,
			}
		}
		var start_time, end_time time.Time
		if cf.TimeRange.Start != "" {
			if t, e := time.Parse(dateWithUTCTimeFormat, cf.TimeRange.Start); e != nil {
				return false, &webDAVerror{
					Code: http.StatusBadRequest,
				}
			} else {
				start_time = t
			}
		}
		if cf.TimeRange.End != "" {
			if t, e := time.Parse(dateWithUTCTimeFormat, cf.TimeRange.End); e != nil {
				return false, &webDAVerror{
					Code: http.StatusBadRequest,
				}
			} else {
				end_time = t
			}
		}
		if timedata, e := parseEvent(comp); e != nil {
			return false, &webDAVerror{
				Code: http.StatusInternalServerError,
			}
		} else if timedata.Intersect(start_time, end_time) {
			return true, nil
		} else {
			return false, nil
		}
	case cf.PropFilters != nil:
		// prop filter not implemented
		return false, &webDAVerror{
			Code: http.StatusNotImplemented,
		}
	case cf.CompFilters != nil:
		return matchCompFiltersWithCompChildren(cf.CompFilters, comp.Children)
	default:
		return true, nil
	}
}

func matchCompFiltersWithCompChildren(cfs []compFilter, children []*ical.Component) (match bool, err error) {
outer:
	for _, cf := range cfs {
		for _, child := range children {
			if child.Name != cf.Name {
				continue
			} else if cf.IsNotDefined != nil {
				return false, nil
			} else if match, err = matchCompFilterWithComp(cf, child); err != nil {
				return false, err
			} else if match {
				continue outer
			}
		}
		// nothing matched
		return false, nil
	}
	// everything matched
	return true, nil
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

// calendar data helper
func CalendarData(cal *ical.Calendar, prop *Prop) (*Any, error) {
	if prop == nil {
		return nil, nil
	}
	var cdata *Any
	for _, val := range prop.Props {
		if val.XMLName == calendarDataName {
			cdata = &val
			break
		}
	}
	if cdata == nil {
		return nil, nil
	}
	if cdata.Content != nil {
		return nil, &webDAVerror{
			Code: http.StatusNotImplemented,
		}
		// 9.6.  CALDAV:calendar-data XML Element . . . . . . . . . . . . . 79
		// 9.6.1.  CALDAV:comp XML Element  . . . . . . . . . . . . . . . 80
		// 9.6.2.  CALDAV:allcomp XML Element . . . . . . . . . . . . . . 81
		// 9.6.3.  CALDAV:allprop XML Element . . . . . . . . . . . . . . 81
		// 9.6.4.  CALDAV:prop XML Element  . . . . . . . . . . . . . . . 82
		// 9.6.5.  CALDAV:expand XML Element  . . . . . . . . . . . . . . 82
		// 9.6.6.  CALDAV:limit-recurrence-set XML Element  . . . . . . . 83
		// 9.6.7.  CALDAV:limit-freebusy-set XML Element  . . . . . . . . 84
		// todo: need to handle something like this
		// <C:calendar-data>
		//   <C:comp name="VCALENDAR">
		//     <C:prop name="VERSION"/>
		//     <C:comp name="VEVENT">
		//       <C:prop name="SUMMARY"/>
		//       <C:prop name="UID"/>
		//       <C:prop name="DTSTART"/>
		//       <C:prop name="DTEND"/>
		//       <C:prop name="DURATION"/>
		//       <C:prop name="RRULE"/>
		//       <C:prop name="RDATE"/>
		//       <C:prop name="EXRULE"/>
		//       <C:prop name="EXDATE"/>
		//       <C:prop name="RECURRENCE-ID"/>
		//     </C:comp>
		//     <C:comp name="VTIMEZONE"/>
		//   </C:comp>
		// </C:calendar-data>
	}

	raw, escaped := bytes.NewBuffer(nil), bytes.NewBuffer(nil)
	if e := ical.NewEncoder(raw).Encode(cal); e != nil {
		// this will be bubbled up to internal server error
		return nil, e
	} else if e := xml.EscapeText(escaped, raw.Bytes()); e != nil {
		// this will be bubbled up to internal server error
		return nil, e
	}
	return &Any{
		XMLName: calendarDataName,
		Attr: []xml.Attr{
			{
				Name:  xml.Name{Local: "content-type"},
				Value: ical.MIMEType,
			},
			{
				Name:  xml.Name{Local: "version"},
				Value: "2.0",
			},
		},
		Content: escaped.Bytes(),
	}, nil
}

// calendar data helper
func AddressData(card vcard.Card, prop *Prop) (*Any, error) {
	if prop == nil {
		return nil, nil
	}
	var adata *Any
	for _, val := range prop.Props {
		if val.XMLName == addressDataName {
			adata = &val
			break
		}
	}
	if adata == nil {
		return nil, nil
	}
	if adata.Content != nil {
		return nil, &webDAVerror{
			Code: http.StatusNotImplemented,
		}
	}

	vcard.ToV4(card)
	raw, escaped := bytes.NewBuffer(nil), bytes.NewBuffer(nil)
	if e := vcard.NewEncoder(raw).Encode(card); e != nil {
		// this will be bubbled up to internal server error
		return nil, e
	} else if e := xml.EscapeText(escaped, raw.Bytes()); e != nil {
		// this will be bubbled up to internal server error
		return nil, e
	}
	return &Any{
		XMLName: addressDataName,
		Attr: []xml.Attr{
			{
				Name:  xml.Name{Local: "content-type"},
				Value: vcard.MIMEType,
			},
			{
				Name:  xml.Name{Local: "version"},
				Value: "4.0",
			},
		},
		Content: escaped.Bytes(),
	}, nil
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

func PropPatchHelper(current_prop *Prop, property_update *PropertyUpdate) (ms *MultiStatus, new_prop *Prop) {
	remove_props, set_props := parsePropertyUpdate(property_update)

	new_props := make([]Any, 0, len(current_prop.Props))

	status_OK := make([]Any, 0, len(current_prop.Props))

outer1:
	for _, val := range current_prop.Props {
		for _, remove := range remove_props {
			if val.XMLName == remove.XMLName {
				status_OK = append(status_OK, Any{XMLName: remove.XMLName})
				continue outer1
			}
		}
		new_props = append(new_props, val)
	}

	status_NotFound := make([]Any, 0, 2)
outer2:
	for _, remove := range remove_props {
		for _, ok := range status_OK {
			if ok.XMLName == remove.XMLName {
				continue outer2
			}
		}
		status_NotFound = append(status_NotFound, Any{XMLName: remove.XMLName})
	}

outer3:
	for _, set := range set_props {
		status_OK = append(status_OK, Any{XMLName: set.XMLName})
		for k, val := range new_props {
			if val.XMLName == set.XMLName {
				new_props[k] = set
				continue outer3
			}
		}
		new_props = append(new_props, set)
	}

	if len(status_NotFound) != 0 {
		resp := Response{
			PropStats: []PropStat{{
				Prop: Prop{
					Props: status_OK,
				},
				Status: statusFailedDependency,
			}, {
				Prop: Prop{
					Props: status_NotFound,
				},
				Status: statusNotFound,
			}},
		}
		ms = &MultiStatus{
			Responses: []Response{resp},
		}
		return
	} else {
		resp := Response{
			PropStats: []PropStat{{
				Prop: Prop{
					Props: status_OK,
				},
				Status: statusOK,
			}},
		}
		ms = &MultiStatus{
			Responses: []Response{resp},
		}
	}
	new_prop = &Prop{
		Props: filterProps(new_props),
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
	if mt, _, e := mime.ParseMediaType(content_type_header); e != nil || mt != ical.MIMEType {
		err = &webDAVerror{
			Code:      http.StatusForbidden,
			Condition: &supportedCalendarDataName,
		}
	} else if c, e := ical.NewDecoder(request_body).Decode(); e != nil {
		err = &webDAVerror{
			Code:      http.StatusForbidden,
			Condition: &validCalendarDataName,
		}
	} else {
		cal = c
	}
	return
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
	} else {
		vcard.ToV4(c)
		card = c
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
			case resourceTypeName:
				var check int
				d := xml.NewDecoder(bytes.NewBuffer(a.Content))
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
						Error:  wrapError(validResourceTypeName),
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
							} else if val != ical.CompEvent {
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
						ResponseDescription: "only VEVENT collections are supported",
					})
				} else {
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
	}
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
