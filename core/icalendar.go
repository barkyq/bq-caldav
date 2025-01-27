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

type compData struct {
	uid          string
	sequence     int64
	dtstart      time.Time
	duration     time.Duration
	rset         *rrule.Set
	recurrenceid time.Time
	attendees    uint64
	summary      string
	description  string
	comp         *ical.Component
}

type CalendarMetaData struct {
	ComponentType string
	comps         []compData
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

func (md *CalendarMetaData) GetUID() (uid string, err error) {
	err = &webDAVerror{
		Code:      http.StatusForbidden,
		Condition: &validCalendarObjectResourceName,
	}
	for _, c := range md.comps {
		if uid == "" {
			uid = c.uid
		} else if uid != c.uid {
			return
		}
	}
	err = nil
	return
}

func intersect_helper(min time.Time, max time.Time, start time.Time, duration time.Duration) bool {
	if max.IsZero() && start.Add(duration).After(min) || start.Equal(min) && duration == 0 {
		return true
	}

	if min.IsZero() && start.Before(max) {
		return true
	}

	if start.Before(max) && start.Add(duration).After(min) || start.Equal(min) && duration == 0 {
		return true
	}
	return false
}

func rrule_count_instances(rset *rrule.Set, max_number_of_instances uint64) bool {
	if rset == nil {
		return true
	} else {
		count := uint64(0)
		next := rset.Iterator()
		for {
			if _, ok := next(); !ok {
				return true
			} else {
				count++
				if count > max_number_of_instances {
					return false
				}
			}
		}
	}
}

func rrule_intersect_helper(min time.Time, max time.Time, rset *rrule.Set, duration time.Duration) bool {
	if t := rset.After(min.Add(-duration), false); !t.IsZero() {
		if max.IsZero() && t.Add(duration).After(min) || t.Equal(min) && duration == 0 {
			return true
		}
		if t.Before(max) && t.Add(duration).After(min) {
			return true
		}
	}
	return false
}

func (data *compData) Intersect(min time.Time, max time.Time) (ok bool) {
	// try first event
	if intersect_helper(min, max, data.dtstart, data.duration) {
		return true
	}
	// now try recurrence; safe for unbounded RRULE
	if min.IsZero() || data.rset == nil {
		return false
	}

	return rrule_intersect_helper(min, max, data.rset, data.duration)
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

func parseJournal(comp *ical.Component) (data *compData, err error) {
	data = &compData{}

	// get UID
	if val := comp.Props.Get(ical.PropUID); val != nil {
		data.uid = val.Value
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
			data.dtstart = t
		}

		switch val.ValueType() {
		case ical.ValueDateTime:
			data.duration = 0
		case ical.ValueDate:
			data.duration = 24 * time.Hour
		}
	}

	repl := strings.NewReplacer("\\n", "\n", "\\,", ",", "\\;", ";", "\\\\", "\\")
	// get summary
	if p := comp.Props.Get(ical.PropSummary); p != nil {
		data.summary = repl.Replace(p.Value)
	}

	// get descriptions
	descriptions := comp.Props.Values(ical.PropDescription)
	b := bytes.NewBuffer(nil)
	for _, v := range descriptions {
		b.WriteString(repl.Replace(v.Value))
	}
	data.description = b.String()
	data.comp = comp
	return
}

func parseEvent(comp *ical.Component) (data *compData, err error) {
	data = &compData{}
	err = fmt.Errorf("parse error")

	// get uid
	if val := comp.Props.Get(ical.PropUID); val != nil {
		data.uid = val.Value
	} else {
		return
	}

	rrule_buf := bytes.NewBuffer(nil)

	if val := comp.Props.Get(ical.PropDateTimeStart); val != nil {
		if t, e := val.DateTime(nil); e != nil {
			err = e
			return
		} else {
			data.dtstart = t
		}

		rrule_buf.WriteString(fmt.Sprintf("%s:%s\n", val.Name, data.dtstart.Format(dateWithUTCTimeFormat)))
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
			data.sequence = s
		}
	}

	// get duration
	if val := comp.Props.Get(ical.PropDuration); val != nil {
		if d, e := parseDuration(val.Value); e != nil {
			err = e
			return
		} else {
			data.duration = d
		}
	} else if comp.Props.Get(ical.PropDateTimeEnd); val != nil {
		if t, e := val.DateTime(nil); e != nil {
			err = e
			return
		} else {
			data.duration = t.Sub(data.dtstart)
		}
	} else {
		switch comp.Props.Get(ical.PropDateTimeStart).ValueType() {
		case ical.ValueDate:
			data.duration = 24 * time.Hour
		default:
			data.duration = 0
		}
	}

	// get recurrenceid
	if val := comp.Props.Get(ical.PropRecurrenceID); val != nil {
		if t, e := val.DateTime(nil); e != nil {
			err = e
			return
		} else {
			data.recurrenceid = t
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
		data.rset = r
	}

	repl := strings.NewReplacer("\\n", "\n", "\\,", ",", "\\;", ";", "\\\\", "\\")
	// get summary
	if p := comp.Props.Get(ical.PropSummary); p != nil {
		data.summary = repl.Replace(p.Value)
	}
	// get description
	if p := comp.Props.Get(ical.PropDescription); p != nil {
		data.description = repl.Replace(p.Value)
	}
	data.comp = comp
	err = nil
	return
}

func parseTodo(comp *ical.Component) (data *compData, err error) {
	data = &compData{}
	err = fmt.Errorf("parse error")

	// get uid
	if val := comp.Props.Get(ical.PropUID); val != nil {
		data.uid = val.Value
	} else {
		return
	}

	rrule_buf := bytes.NewBuffer(nil)

	if val := comp.Props.Get(ical.PropDateTimeStart); val != nil {
		if t, e := val.DateTime(nil); e != nil {
			err = e
			return
		} else {
			data.dtstart = t
		}
	}

	// get due OR duration
	if val := comp.Props.Get(ical.PropDue); val != nil {
		var due time.Time
		if t, e := val.DateTime(nil); e != nil {
			err = e
			return
		} else {
			due = t
		}
		if data.dtstart.IsZero() {
			data.dtstart = due
		} else {
			data.duration = due.Sub(data.dtstart)
		}
	} else if val := comp.Props.Get(ical.PropDuration); val != nil {
		if data.dtstart.IsZero() {
			// cannot have duration without dtstart
			return
		} else if d, e := parseDuration(val.Value); e != nil {
			err = e
			return
		} else {
			data.duration = d
		}
	}

	if !data.dtstart.IsZero() {
		// potentially an rrule
		rrule_buf.WriteString(fmt.Sprintf("%s:%s\n", "DTSTART", data.dtstart.Format(dateWithUTCTimeFormat)))

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
			data.rset = r
		}
	} else {
		// dtstart was not set yet; assume completed/created handling
		var created, completed time.Time
		if val := comp.Props.Get(ical.PropCompleted); val != nil {
			if t, e := val.DateTime(nil); e != nil {
				err = e
				return
			} else {
				completed = t
			}
		}
		if val := comp.Props.Get(ical.PropCreated); val != nil {
			if t, e := val.DateTime(nil); e != nil {
				err = e
				return
			} else {
				created = t
			}
		}
		if created.IsZero() {
			data.dtstart = completed
			data.duration = 0
		} else if completed.IsZero() {
			data.dtstart = created
			data.duration = 0
		} else {
			data.dtstart = created
			data.duration = completed.Sub(created)
		}
	}

	if data.dtstart.IsZero() {
		// still zero??
		// then should match every filter, so make a wide window
		data.dtstart = time.Date(1984, time.November, 11, 16, 20, 0, 0, nil)
		// 200 years
		data.duration = 1752000 * time.Hour
	}

	// get sequence
	if val := comp.Props.Get(ical.PropSequence); val != nil {
		if s, e := strconv.ParseInt(val.Value, 10, 64); e != nil {
			err = e
			return
		} else {
			data.sequence = s
		}
	}

	// get recurrenceid
	if val := comp.Props.Get(ical.PropRecurrenceID); val != nil {
		if t, e := val.DateTime(nil); e != nil {
			err = e
			return
		} else {
			data.recurrenceid = t
		}
	}

	repl := strings.NewReplacer("\\n", "\n", "\\,", ",", "\\;", ";", "\\\\", "\\")
	// get summary
	if p := comp.Props.Get(ical.PropSummary); p != nil {
		data.summary = repl.Replace(p.Value)
	}
	// get description
	if p := comp.Props.Get(ical.PropDescription); p != nil {
		data.description = repl.Replace(p.Value)
	}

	data.comp = comp
	err = nil
	return
}

func parseCalendarComponent(comp *ical.Component) (data *compData, err error) {
	err = &webDAVerror{
		Code:      http.StatusForbidden,
		Condition: &validCalendarObjectResourceName,
	}

	switch comp.Name {
	case ical.CompEvent:
		if edt, e := parseEvent(comp); e != nil {
			return
		} else {
			data = edt
		}
	case ical.CompJournal:
		if jdt, e := parseJournal(comp); e != nil {
			return
		} else {
			data = jdt
		}
	case ical.CompToDo:
		if tdt, e := parseTodo(comp); e != nil {
			return
		} else {
			data = tdt
		}
	case ical.CompFreeBusy:
		// not implemented
		err = &webDAVerror{
			Code:      http.StatusForbidden,
			Condition: &supportedCalendarComponentName,
		}
		return
	default:
		return
	}
	err = nil
	return
}

func ParseCalendarObjectResource(cal *ical.Calendar) (metadata *CalendarMetaData, err error) {
	var component_type string
	err = &webDAVerror{
		Code:      http.StatusForbidden,
		Condition: &validCalendarObjectResourceName,
	}

	if methodp := cal.Props.Get(ical.PropMethod); methodp != nil {
		return
	}

	comps := make([]compData, 0, len(cal.Children))
	for _, child := range cal.Children {
		if child.Name == ical.CompTimezone {
			continue
		} else if component_type == "" {
			component_type = child.Name
		} else if child.Name != component_type {
			return
		}
		if comp, e := parseCalendarComponent(child); e != nil {
			err = e
			return
		} else {
			comps = append(comps, *comp)
		}
	}

	metadata = &CalendarMetaData{component_type, comps}
	err = nil
	return
}
