package core

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/emersion/go-ical"
	"github.com/teambition/rrule-go"
)

type eventData struct {
	uid          string
	sequence     int64
	dtstart      time.Time
	duration     time.Duration
	rset         *rrule.Set
	recurrenceid time.Time
	event        *ical.Component
}

type journalData struct {
	uid          string
	dtstart      time.Time
	summary      string
	descriptions []string
	journal      *ical.Component
}

type calendarMetaData struct {
	ComponentType string
	events        []eventData
	journal       []journalData
}

const dateFormat = "20060102"
const dateTimeFormat = "20060102T150405"
const dateWithUTCTimeFormat = "20060102T150405Z"

var maxTime = time.Now().AddDate(100, 0, 0)

var symbolmap = map[string]int64{
	"W": 7 * 24 * 60 * 60,
	"D": 24 * 60 * 60,
	"H": 60 * 60,
	"M": 60,
	"S": 60,
}

func (edt *eventData) Intersect(min time.Time, max time.Time) (ok bool) {

	// try first event
	if max.IsZero() && edt.dtstart.Add(edt.duration).After(min) || edt.dtstart.Equal(min) && edt.duration == 0 {
		return true
	}

	if min.IsZero() && edt.dtstart.Before(max) {
		return true
	}

	if edt.dtstart.Before(max) && edt.dtstart.Add(edt.duration).After(min) || edt.dtstart.Equal(min) && edt.duration == 0 {
		return true
	}

	// now try recurrence; safe for unbounded RRULE
	if min.IsZero() {
		return
	}

	if t := edt.rset.After(min.Add(-edt.duration), false); !t.IsZero() {
		if max.IsZero() && t.Add(edt.duration).After(min) || t.Equal(min) && edt.duration == 0 {
			return true
		}
		if t.Before(max) && t.Add(edt.duration).After(min) {
			return true
		}
	}

	return
}

func parseDuration(val string) (dur time.Duration, err error) {
	var minus bool
	var seconds int64
	if val[0] == '-' {
		minus = true
	}
	val = strings.Trim(val, "-+P")
	for k, m := range symbolmap {
		if before, after, found := strings.Cut(val, k); found {
			if x, e := strconv.ParseInt(before, 10, 64); e != nil {
				err = e
				return
			} else {
				seconds += x * m
				val = strings.TrimPrefix(after, "T")
			}
		}
	}
	if minus {
		seconds = -seconds
	}
	return time.Duration(seconds) * time.Second, nil
}

func parseJournal(comp *ical.Component) (jdt *journalData, err error) {
	jdt = &journalData{}

	// get UID
	if val := comp.Props.Get(ical.PropUID); val != nil {
		jdt.uid = val.Value
	} else {
		err = fmt.Errorf("parse error")
		return
	}

	// get DTSTART; not required
	// if there is no dtstart, it should not match any filter
	// so we can leave it unset
	if val := comp.Props.Get(ical.PropDateTimeStart); val != nil {
		if t, e := val.DateTime(nil); e != nil {
			err = e
			return
		} else {
			jdt.dtstart = t
		}
	}

	repl := strings.NewReplacer("\\n", "\n", "\\,", ",", "\\;", ";", "\\\\", "\\")
	// get summary
	if p := comp.Props.Get(ical.PropSummary); p != nil {
		jdt.summary = repl.Replace(p.Value)
	}

	// get descriptions
	descriptions := comp.Props.Values(ical.PropDescription)
	jdt.descriptions = make([]string, len(descriptions))
	for k, v := range descriptions {
		jdt.descriptions[k] = repl.Replace(v.Value)
	}
	jdt.journal = comp
	return
}

func parseEvent(comp *ical.Component) (timedata *eventData, err error) {
	timedata = &eventData{}
	err = fmt.Errorf("parse error")

	// get uid
	if val := comp.Props.Get(ical.PropUID); val != nil {
		timedata.uid = val.Value
	} else {
		return
	}

	rrule_buf := bytes.NewBuffer(nil)

	if val := comp.Props.Get(ical.PropDateTimeStart); val != nil {
		if t, e := val.DateTime(nil); e != nil {
			err = e
			return
		} else {
			timedata.dtstart = t
		}

		rrule_buf.WriteString(fmt.Sprintf("%s:%s\n", val.Name, timedata.dtstart.Format(dateWithUTCTimeFormat)))
	} else {
		// need DTSTART
		return
	}

	// get sequence
	if val := comp.Props.Get(ical.PropSequence); val != nil {
		if s, e := strconv.ParseInt(val.Value, 10, 64); e != nil {
			err = e
			return
		} else {
			timedata.sequence = s
		}
	}

	// get duration
	if val := comp.Props.Get(ical.PropDuration); val != nil {
		if d, e := parseDuration(val.Value); e != nil {
			err = e
			return
		} else {
			timedata.duration = d
		}
	} else if comp.Props.Get(ical.PropDateTimeEnd); val != nil {
		if t, e := val.DateTime(nil); e != nil {
			err = e
			return
		} else {
			timedata.duration = t.Sub(timedata.dtstart)
		}
	} else {
		switch comp.Props.Get(ical.PropDateTimeStart).ValueType() {
		case ical.ValueDate:
			timedata.duration = 24 * time.Hour
		default:
			timedata.duration = 0
		}
	}

	// get recurrenceid
	if val := comp.Props.Get(ical.PropRecurrenceID); val != nil {
		if t, e := val.DateTime(nil); e != nil {
			err = e
			return
		} else {
			timedata.recurrenceid = t
		}
	}
	// recurrence rule
	if val := comp.Props.Get(ical.PropRecurrenceRule); val != nil {
		rrule_buf.WriteString(fmt.Sprintf("%s:%s\n", val.Name, val.Value))
	}

	if val := comp.Props.Get(ical.PropRecurrenceDates); val != nil {
		rrule_buf.WriteString(fmt.Sprintf("%s", val.Name))
		switch val.ValueType() {
		case ical.ValueDate:
			rrule_buf.WriteString(fmt.Sprintf(";VALUE=DATE:%s", val.Value))
		case ical.ValueDateTime:
			if tzid := val.Params.Get(ical.ParamTimezoneID); tzid != "" {
				rrule_buf.WriteString(fmt.Sprintf(";TZID=%s", tzid))
			}
			rrule_buf.WriteString(fmt.Sprintf(":%s\n", val.Value))
		case ical.ValuePeriod:
			// do not allow VALUE=PERIOD
			return
		default:
			// not allowed by RFC
			return
		}
	}

	if val := comp.Props.Get(ical.PropExceptionDates); val != nil {
		rrule_buf.WriteString(fmt.Sprintf("%s", val.Name))
		switch val.ValueType() {
		case ical.ValueDate:
			rrule_buf.WriteString(fmt.Sprintf(";VALUE=DATE:%s", val.Value))
		case ical.ValueDateTime:
			if tzid := val.Params.Get(ical.ParamTimezoneID); tzid != "" {
				rrule_buf.WriteString(fmt.Sprintf(";TZID=%s", tzid))
			}
			rrule_buf.WriteString(fmt.Sprintf(":%s\n", val.Value))
		default:
			// not allowed by RFC
			return
		}
	}
	if r, e := rrule.StrToRRuleSet(rrule_buf.String()); e != nil {
		return
	} else {
		timedata.rset = r
	}

	timedata.event = comp
	err = nil
	return
}

func ParseCalendarObjectResource(cal *ical.Calendar) (metadata *calendarMetaData, err error) {
	var component_type string
	err = &webDAVerror{
		Code:      http.StatusForbidden,
		Condition: &validCalendarObjectResourceName,
	}

	if methodp := cal.Props.Get(ical.PropMethod); methodp != nil {
		return
	}

	events := make([]eventData, 0, len(cal.Children))
	journals := make([]journalData, 0, len(cal.Children))
	for _, child := range cal.Children {
		if child.Name == ical.CompTimezone {
			continue
		} else if component_type == "" {
			component_type = child.Name
		} else if child.Name != component_type {
			return
		}
		switch child.Name {
		case ical.CompEvent:
			if edt, e := parseEvent(child); e != nil {
				return
			} else {
				events = append(events, *edt)
			}
		case ical.CompJournal:
			if jdt, e := parseJournal(child); e != nil {
				return
			} else {
				journals = append(journals, *jdt)
			}
		case ical.CompToDo, ical.CompFreeBusy:
			// not implemented
			err = &webDAVerror{
				Code:      http.StatusForbidden,
				Condition: &supportedCalendarComponentName,
			}
			return
		default:
			return
		}
	}

	metadata = &calendarMetaData{component_type, events, journals}
	err = nil
	return
}
