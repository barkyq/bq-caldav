package core

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/emersion/go-ical"
)

// https://datatracker.ietf.org/doc/html/rfc4918#section-14.20
// propname OR allprop, include? OR prop
type PropFind struct {
	XMLName  xml.Name  `xml:"DAV: propfind"`
	PropName *struct{} `xml:"propname"`
	AllProp  *struct{} `xml:"allprop"`
	Include  *Include  `xml:"include"`
	Prop     *Prop     `xml:"prop"`
}

// https://datatracker.ietf.org/doc/html/rfc4918#section-14.8
type Include struct {
	XMLName    xml.Name `xml:"DAV: include"`
	Inclusions []Any    `xml:",any"`
}

// https://tools.ietf.org/html/rfc4918#section-14.18
type Prop struct {
	XMLName xml.Name `xml:"DAV: prop"`
	Props   []Any    `xml:",any"`
}

type Any struct {
	XMLName xml.Name   `xml:""`
	Content []byte     `xml:",innerxml"`
	Attr    []xml.Attr `xml:",attr,omitempty"`
}

// https://tools.ietf.org/html/rfc4918#section-15.9
type resourceType struct {
	XMLName       xml.Name `xml:"DAV: resourcetype"`
	ResourceTypes []Any    `xml:",any"`
}

var (
	creationDateName         = xml.Name{Space: "DAV:", Local: "creationdate"}
	displayNameName          = xml.Name{Space: "DAV:", Local: "displayname"}
	getContentLanguageName   = xml.Name{Space: "DAV:", Local: "getcontentlanguage"}
	getContentLengthName     = xml.Name{Space: "DAV:", Local: "getcontentlength"}
	getContentTypeName       = xml.Name{Space: "DAV:", Local: "getcontenttype"}
	getETagName              = xml.Name{Space: "DAV:", Local: "getetag"}
	getLastModifiedName      = xml.Name{Space: "DAV:", Local: "getlastmodified"}
	resourceTypeName         = xml.Name{Space: "DAV:", Local: "resourcetype"}
	collectionTypeName       = xml.Name{Space: "DAV:", Local: "collection"}
	currentUserPrincipalName = xml.Name{Space: "DAV:", Local: "current-user-principal"}
	principalURLName         = xml.Name{Space: "DAV:", Local: "principal-URL"}

	calendarTypeName                  = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "calendar"}
	calendarHomeSetName               = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "calendar-home-set"}
	calendarQueryName                 = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "calendar-query"}
	calendarMultiGetName              = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "calendar-multiget"}
	calendarDataName                  = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "calendar-data"}
	supportedCalendarComponentSetName = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "supported-calendar-component-set"}
	compName                          = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "comp"}
	calendarTimezoneName              = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "calendar-timezone"}
	calendarMaxResourceSizeName       = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "max-resource-size"}
	minDateTimeName                   = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "min-date-time"}
	maxDateTimeName                   = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "max-date-time"}
	maxInstancesName                  = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "max-instances"}
	maxAttendeesPerInstanceName       = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "max-attendees-per-instance"}
	calendarSupportedCollationSetName = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "supported-collation-set"}

	addressbookTypeName                  = xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "addressbook"}
	addressbookHomeSetName               = xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "addressbook-home-set"}
	principalAddressName                 = xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "principal-address"}
	addressbookQueryName                 = xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "addressbook-query"}
	addressbookMultiGetName              = xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "addressbook-multiget"}
	addressDataName                      = xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "address-data"}
	supportedAddressDataName             = xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "supported-address-data"}
	addressDataTypeName                  = xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "address-data-type"}
	addressbookMaxResourceSizeName       = xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "max-resource-size"}
	addressbookSupportedCollationSetName = xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "supported-collation-set"}
)

var allpropInclusions = []xml.Name{
	creationDateName,
	displayNameName,
	getContentLanguageName,
	getContentLengthName,
	getContentTypeName,
	getETagName,
	getLastModifiedName,
	resourceTypeName,
}

// https://tools.ietf.org/html/rfc4918#section-14.16
type MultiStatus struct {
	XMLName             xml.Name   `xml:"DAV: multistatus"`
	Responses           []Response `xml:"response"`
	ResponseDescription string     `xml:"responsedescription,omitempty"`
}

// either 1 Href and 1+ PropStats 0 Status
// or 1+ Href and 1 status
//
// https://datatracker.ietf.org/doc/html/rfc4918#section-14.24
type Response struct {
	XMLName             xml.Name   `xml:"DAV: response"`
	Hrefs               []Href     `xml:"href"`
	PropStats           []PropStat `xml:"propstat,omitempty"`
	ResponseDescription string     `xml:"responsedescription,omitempty"`
	Status              *status    `xml:"status,omitempty"`
	Error               *davError  `xml:"error,omitempty"`
	Location            *location  `xml:"location,omitempty"`
}

// https://datatracker.ietf.org/doc/html/rfc4918#section-14.9
//
// # Location is typically used after MOVE or COPY
type location struct {
	XMLName xml.Name `xml:"DAV: location"`
	Href    Href     `xml:"href"`
}

type Href struct {
	XMLName xml.Name `xml:"DAV: href"`
	Target  string   `xml:",chardata"`
}

// https://datatracker.ietf.org/doc/html/rfc4918#section-14.22
type PropStat struct {
	XMLName             xml.Name  `xml:"DAV: propstat"`
	Prop                Prop      `xml:"prop"`
	Status              status    `xml:"status"`
	ResponseDescription string    `xml:"responsedescription,omitempty"`
	Error               *davError `xml:"error,omitempty"`
}

// https://datatracker.ietf.org/doc/html/rfc4918#section-14.28
type status struct {
	XMLName xml.Name `xml:"DAV: status"`
	Text    string   `xml:",chardata"`
}

type davError struct {
	XMLName    xml.Name `xml:"DAV: error"`
	Conditions []Any    `xml:",any"`
}

// for PROPPATCH
type PropertyUpdate struct {
	XMLName xml.Name `xml:"DAV: propertyupdate"`
	Set     []Prop   `xml:"set>prop"`
	Remove  []Prop   `xml:"remove>prop"`
}

// preconditions/postconditions

var (
	validResourceTypeName           = xml.Name{Space: "DAV", Local: "valid-resourcetype"}
	supportedCalendarDataName       = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "supported-calendar-data"}
	validCalendarDataName           = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "valid-calendar-data"}
	validCalendarObjectResourceName = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "valid-calendar-object-resource"}
	supportedCalendarComponentName  = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "supported-calendar-component"}
	calendarNoUIDConflictName       = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "no-uid-conflict"}
	supportedFilterName             = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "supported-filter"}

	addressbookNoUIDConflictName = xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "no-uid-conflict"}
	validAddressDataName         = xml.Name{Space: "urn:ietf:params:xml:ns:carddav", Local: "valid-address-data"}
)

// Report Sets
type supportedReportSet struct {
	XMLName          xml.Name          `xml:"DAV: supported-report-set"`
	SupportedReports []supportedReport `xml:"supported-report"`
}

type supportedReport struct {
	XMLName xml.Name `xml:"DAV: supported-report"`
	Report  report   `xml:"report"`
}

type report struct {
	XMLName xml.Name `xml:"DAV: report"`
	Value   Any      `xml:",any"`
}

// Calendar Props
type calendarHomeSet struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:caldav calendar-home-set"`
	Href    Href     `xml:"href"`
}

// calendar data elements
type CalendarDataReq struct {
	XMLName            xml.Name      `xml:"urn:ietf:params:xml:ns:caldav calendar-data"`
	Expand             *timeInterval `xml:"urn:ietf:params:xml:ns:caldav expand"`
	LimitRecurrenceSet *timeInterval `xml:"urn:ietf:params:xml:ns:caldav limit-recurrence-set"`
	LimitFreeBusySet   *timeInterval `xml:"urn:ietf:params:xml:ns:caldav limit-freebusy-set"`
	CompReq            *compReq      `xml:"urn:ietf:params:xml:ns:caldav comp"`
}

type timeInterval struct {
	start time.Time
	end   time.Time
}

func (ti *timeInterval) UnmarshalXML(d *xml.Decoder, start xml.StartElement) (err error) {
	err = &webDAVerror{
		Code: http.StatusBadRequest,
	}
	for _, a := range start.Attr {
		if a.Name.Local == "start" {
			if t, e := time.Parse(dateWithUTCTimeFormat, a.Value); e != nil {
				return
			} else {
				ti.start = t
			}
		} else if a.Name.Local == "end" {
			if t, e := time.Parse(dateWithUTCTimeFormat, a.Value); e != nil {
				return
			} else {
				ti.end = t
			}
		}
	}
	return d.Skip()
}

type compReq struct {
	XMLName xml.Name  `xml:"urn:ietf:params:xml:ns:caldav comp"`
	Name    string    `xml:"name,attr"`
	Allprop *struct{} `xml:"urn:ietf:params:xml:ns:caldav allprop"`
	Allcomp *struct{} `xml:"urn:ietf:params:xml:ns:caldav allcomp"`
	Props   []propReq `xml:"urn:ietf:params:xml:ns:caldav prop"`
	Comps   []compReq `xml:"urn:ietf:params:xml:ns:caldav comp"`
}

type propReq struct {
	Name    string
	NoValue bool
}

func (pr *propReq) UnmarshalXML(d *xml.Decoder, start xml.StartElement) (err error) {
	for _, a := range start.Attr {
		if a.Name.Local == "name" {
			pr.Name = a.Value
		} else if a.Name.Local == "novalue" {
			if a.Value == "yes" {
				pr.NoValue = true
			}
		}
	}
	if pr.Name == "" {
		return fmt.Errorf("name is required")
	} else {
		return d.Skip()
	}
}

// Calendar Report Elements
//

// https://datatracker.ietf.org/doc/html/rfc4791#section-9.5
type Query struct {
	XMLName           xml.Name           `xml:""`
	AllProp           *struct{}          `xml:"DAV: allprop"`
	PropName          *struct{}          `xml:"DAV: propname"`
	Prop              *Prop              `xml:"DAV: prop"`
	CalendarFilter    *calendarfilter    `xml:"urn:ietf:params:xml:ns:caldav filter"`
	AddressbookFilter *addressbookfilter `xml:"urn:ietf:params:xml:ns:carddav filter"`
	Timezone          *Timezone          `xml:"urn:ietf:params:xml:ns:caldav calendar-timezone"`
	CalendarData      *CalendarDataReq   `xml:"-"`
}

type Timezone struct {
	Location *time.Location
}

func (tz *Timezone) UnmarshalXML(d *xml.Decoder, start xml.StartElement) (err error) {
	err = fmt.Errorf("invalid timezone data")
	if t, e := d.Token(); e != nil {
		//
	} else if cd, ok := t.(xml.CharData); !ok {
		//
	} else if br := bytes.NewReader(cd); false {
		//
	} else if tz_cal, e := ical.NewDecoder(br).Decode(); e != nil || len(tz_cal.Children) != 1 {
		//
	} else if tz_comp := tz_cal.Children[0]; tz_comp.Name != ical.CompTimezone {
		//
	} else if tz_id_prop := tz_comp.Props.Get(ical.PropTimezoneID); tz_id_prop == nil {
		//
	} else if loc, e := time.LoadLocation(tz_id_prop.Value); e != nil {
		err = e
	} else {
		tz.Location = loc
		err = nil
	}
	return
}

// https://datatracker.ietf.org/doc/html/rfc4791#section-9.7
type calendarfilter struct {
	XMLName    xml.Name   `xml:"urn:ietf:params:xml:ns:caldav filter"`
	CompFilter compFilter `xml:"comp-filter"`
}

// https://datatracker.ietf.org/doc/html/rfc4791#section-9.7
type addressbookfilter struct {
	XMLName    xml.Name              `xml:"urn:ietf:params:xml:ns:carddav filter"`
	PropFilter addressbookPropFilter `xml:"prop-filter"`
}

// https://tools.ietf.org/html/rfc4791#section-9.7.1
type compFilter struct {
	XMLName      xml.Name             `xml:"urn:ietf:params:xml:ns:caldav comp-filter"`
	Name         string               `xml:"name,attr"`
	IsNotDefined *struct{}            `xml:"is-not-defined"`
	TimeRange    *timeInterval        `xml:"time-range"`
	PropFilters  []calendarPropFilter `xml:"prop-filter"`
	CompFilters  []compFilter         `xml:"comp-filter"`
}

// https://tools.ietf.org/html/rfc4791#section-9.7.2
type calendarPropFilter struct {
	XMLName      xml.Name      `xml:"urn:ietf:params:xml:ns:caldav prop-filter"`
	Name         string        `xml:"name,attr"`
	IsNotDefined *struct{}     `xml:"is-not-defined"`
	TimeRange    *timeInterval `xml:"time-range"`
	TextMatch    *textMatch    `xml:"text-match"`
	ParamFilter  []paramFilter `xml:"param-filter"`
}

// https://tools.ietf.org/html/rfc4791#section-9.7.2
type addressbookPropFilter struct {
	XMLName      xml.Name      `xml:"urn:ietf:params:xml:ns:carddav prop-filter"`
	Name         string        `xml:"name,attr"`
	IsNotDefined *struct{}     `xml:"is-not-defined"`
	TextMatch    *textMatch    `xml:"text-match"`
	ParamFilter  []paramFilter `xml:"param-filter"`
}

// https://tools.ietf.org/html/rfc4791#section-9.7.3
type paramFilter struct {
	XMLName      xml.Name   `xml:""`
	Name         string     `xml:"name,attr"`
	IsNotDefined *struct{}  `xml:"is-not-defined"`
	TextMatch    *textMatch `xml:"text-match"`
}

// https://datatracker.ietf.org/doc/html/rfc4791#section-9.7.5
type textMatch struct {
	XMLName         xml.Name `xml:""`
	Text            string   `xml:",chardata"`
	Collation       string   `xml:"collation,attr"`
	NegateCondition string   `xml:"negate-condition,attr"`
}

// https://datatracker.ietf.org/doc/html/rfc4791#section-9.5
type Multiget struct {
	XMLName      xml.Name         `xml:""`
	AllProp      *struct{}        `xml:"DAV: allprop"`
	PropName     *struct{}        `xml:"DAV: propname"`
	Prop         *Prop            `xml:"DAV: prop"`
	Hrefs        []Href           `xml:"DAV: href"`
	Timezone     *Timezone        `xml:"ietf:params:xml:ns:caldav calendar-timezone"`
	CalendarData *CalendarDataReq `xml:"-"`
}

type reportReq struct {
	Query    *Query
	Multiget *Multiget
}

type HasCalendarDataProp interface {
	getCalendarData() (cdata *Any)
}

func (m *Multiget) getCalendarData() (cdata *Any) {
	if m.Prop == nil {
		return nil
	}
	for _, val := range m.Prop.Props {
		if val.XMLName == calendarDataName {
			cdata = &val
			break
		}
	}
	return
}

func (q *Query) getCalendarData() (cdata *Any) {
	if q.Prop == nil {
		return nil
	}
	for _, val := range q.Prop.Props {
		if val.XMLName == calendarDataName {
			cdata = &val
			break
		}
	}
	return
}

func (r *reportReq) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var v interface{}
	switch start.Name {
	case calendarQueryName, addressbookQueryName:
		r.Query = &Query{}
		v = r.Query
	case calendarMultiGetName, addressbookMultiGetName:
		r.Multiget = &Multiget{}
		v = r.Multiget
	default:
		return &webDAVerror{http.StatusBadRequest, nil, nil}
	}

	return d.DecodeElement(v, &start)
}

// mkcol and mkcalendar
// https://datatracker.ietf.org/doc/html/rfc4791#section-9.5

type mkColRequest struct {
	XMLName xml.Name `xml:""`
	Props   []Prop   `xml:"set>prop"`
}

func (r *Any) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	r.XMLName = start.Name
	r.Attr = make([]xml.Attr, 0, 2)
	for _, k := range start.Attr {
		if k.Name.Space == "xmlns" || k.Name.Local == "xmlns" {
			continue
		} else {
			r.Attr = append(r.Attr, k)
		}
	}
	buf := bytes.NewBuffer(nil)
	var depth int
	for {
		if tok, e := d.Token(); e != nil {
			if errors.Is(e, io.EOF) {
				r.Content = buf.Bytes()
				return nil
			} else {
				return e
			}
		} else {
			switch t := tok.(type) {
			case xml.StartElement:
				depth++
				var attrs string
				if s := t.Name.Space; s != "" {
					attrs = fmt.Sprintf(" xmlns=\"%s\"", s)
				}
				for _, a := range t.Attr {
					if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
						continue
					} else {
						attrs = attrs + fmt.Sprintf(" %s=\"%s\"", a.Name.Local, a.Value)
					}
				}
				buf.WriteString(fmt.Sprintf("<%s%s>", t.Name.Local, attrs))
			case xml.EndElement:
				if depth > 0 {
					buf.WriteString(fmt.Sprintf("</%s>", t.Name.Local))
					depth--
				}
			case xml.CharData:
				if bytes.TrimSpace(t) != nil {
					xml.EscapeText(buf, t)
				}
			}
		}
	}
}

type supportedAddressData struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:carddav supported-address-data"`
	DataTypes []Any
}

var (
	mkcolRequestName      = xml.Name{Space: "DAV:", Local: "mkcol"}
	mkcalendarRequestName = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "mkcalendar"}
)

type mkColResponse struct {
	XMLName   xml.Name   `xml:"DAV: mkcol-response"`
	PropStats []PropStat `xml:"DAV: propstat"`
}

type mkCalendarResponse struct {
	XMLName   xml.Name   `xml:"urn:ietf:params:xml:ns:caldav mkcalendar-response"`
	PropStats []PropStat `xml:"DAV: propstat"`
}
