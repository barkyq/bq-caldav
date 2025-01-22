package core

import (
	"encoding/xml"
	"fmt"
)

// https://datatracker.ietf.org/doc/html/rfc4918#section-14.20
// propname OR allprop, include? OR prop
type PropFind struct {
	XMLName  xml.Name  `xml:"DAV: propfind"`
	PropName *struct{} `xml:"propname,omitempty"`
	AllProp  *struct{} `xml:"allprop,omitempty"`
	Include  *Include  `xml:"include,omitempty"`
	Prop     *Prop     `xml:"prop,omitempty"`
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
	Attrs   []xml.Attr `xml:",attr,omitempty"`
}

// https://tools.ietf.org/html/rfc4918#section-15.9
type ResourceType struct {
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
	supportedCalendarDataName       = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "supported-calendar-data"}
	validCalendarDataName           = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "valid-calendar-data"}
	validCalendarObjectResourceName = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "valid-calendar-object-resource"}
	supportedCalendarComponentName  = xml.Name{Space: "urn:ietf:params:xml:ns:caldav", Local: "supported-calendar-component"}
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

// https://datatracker.ietf.org/doc/html/rfc4791#section-9.5
type mkCalendarRequest struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:caldav mkcalendar"`
	Set     *Prop    `xml:"set>prop"`
}

type mkCalendarResponse struct {
	XMLName  xml.Name `xml:"urn:ietf:params:xml:ns:caldav mkcalendar-response"`
	PropStat PropStat `xml:"DAV: propstat"`
}

type calendarTimezone struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:caldav calendar-timezone"`
	Content []byte   `xml:",chardata"`
}

// Calendar Report Elements
//

// https://datatracker.ietf.org/doc/html/rfc4791#section-9.5
type CalendarQuery struct {
	XMLName  xml.Name  `xml:"urn:ietf:params:xml:ns:caldav calendar-query"`
	AllProp  *struct{} `xml:"DAV: allprop,omitempty"`
	PropName *struct{} `xml:"DAV: propname,omitempty"`
	Prop     *Prop     `xml:"DAV: prop,omitempty"`
	Filter   filter    `xml:"filter"`
	// TODO: timezone
}

// https://datatracker.ietf.org/doc/html/rfc4791#section-9.7
type filter struct {
	XMLName    xml.Name   `xml:"urn:ietf:params:xml:ns:caldav filter"`
	CompFilter compFilter `xml:"comp-filter"`
}

// https://tools.ietf.org/html/rfc4791#section-9.7.1
type compFilter struct {
	XMLName      xml.Name     `xml:"urn:ietf:params:xml:ns:caldav comp-filter"`
	Name         string       `xml:"name,attr"`
	IsNotDefined *struct{}    `xml:"is-not-defined,omitempty"`
	TimeRange    *timeRange   `xml:"time-range,omitempty"`
	PropFilters  []propFilter `xml:"prop-filter,omitempty"`
	CompFilters  []compFilter `xml:"comp-filter,omitempty"`
}

// https://tools.ietf.org/html/rfc4791#section-9.7.2
type propFilter struct {
	XMLName      xml.Name      `xml:"urn:ietf:params:xml:ns:caldav prop-filter"`
	Name         string        `xml:"name,attr"`
	IsNotDefined *struct{}     `xml:"is-not-defined,omitempty"`
	TimeRange    *timeRange    `xml:"time-range,omitempty"`
	TextMatch    *textMatch    `xml:"text-match,omitempty"`
	ParamFilter  []paramFilter `xml:"param-filter,omitempty"`
}

// https://tools.ietf.org/html/rfc4791#section-9.7.3
type paramFilter struct {
	XMLName      xml.Name   `xml:"urn:ietf:params:xml:ns:caldav param-filter"`
	Name         string     `xml:"name,attr"`
	IsNotDefined *struct{}  `xml:"is-not-defined,omitempty"`
	TextMatch    *textMatch `xml:"text-match,omitempty"`
}

// https://datatracker.ietf.org/doc/html/rfc4791#section-9.7.5
type textMatch struct {
	XMLName         xml.Name `xml:"urn:ietf:params:xml:ns:caldav text-match"`
	Text            string   `xml:",chardata"`
	Collation       string   `xml:"collation,attr,omitempty"`
	NegateCondition string   `xml:"negate-condition,attr,omitempty"`
}

// https://datatracker.ietf.org/doc/html/rfc4791#section-9.9
type timeRange struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:caldav time-range"`
	Start   string   `xml:"start,attr,omitempty"`
	End     string   `xml:"end,attr,omitempty"`
}

// https://datatracker.ietf.org/doc/html/rfc4791#section-9.5
type CalendarMultiget struct {
	XMLName  xml.Name  `xml:"urn:ietf:params:xml:ns:caldav calendar-multiget"`
	AllProp  *struct{} `xml:"DAV: allprop,omitempty"`
	PropName *struct{} `xml:"DAV: propname,omitempty"`
	Prop     *Prop     `xml:"DAV: prop,omitempty"`
	Hrefs    []Href    `xml:"DAV: href"`
	// TODO: timezone
}

type reportReq struct {
	Query    *CalendarQuery
	Multiget *CalendarMultiget
	// TODO: CALDAV:free-busy-query
}

func (r *reportReq) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var v interface{}
	switch start.Name {
	case calendarQueryName:
		r.Query = &CalendarQuery{}
		v = r.Query
	case calendarMultiGetName:
		r.Multiget = &CalendarMultiget{}
		v = r.Multiget
	default:
		return fmt.Errorf("caldav: unsupported REPORT root %q %q", start.Name.Space, start.Name.Local)
	}

	return d.DecodeElement(v, &start)
}
