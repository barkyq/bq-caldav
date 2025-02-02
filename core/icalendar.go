package core

import (
	"bytes"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/emersion/go-ical"
	"github.com/teambition/rrule-go"
)

type compData struct {
	uid          string
	dtstart      time.Time
	duration     time.Duration
	start_name   string
	end_name     string
	rrule        *rrule.RRule
	recurrenceid time.Time
	attendees    uint64
	freebusy     []Period
	comp         *ical.Component
}

type Period struct {
	start    time.Time
	duration time.Duration
}

type CalendarMetaData struct {
	ComponentType string
	exdates       []time.Time
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
	if start.IsZero() {
		return false
	}

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

func rrule_count_instances(rrule *rrule.RRule, max_number_of_instances uint64) bool {
	if rrule == nil {
		return true
	} else {
		count := uint64(0)
		next := rrule.Iterator()
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

func rrule_intersect_helper(min time.Time, max time.Time, rrule *rrule.RRule, duration time.Duration) bool {
	if min.IsZero() || rrule == nil {
		return false
	} else if t := rrule.After(min.Add(-duration), false); !t.IsZero() {
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

	// now try freebusy
	if periods := data.freebusy; periods != nil {
		for _, period := range periods {
			if intersect_helper(min, max, period.start, period.duration) {
				return true
			}
		}
		return false
	}

	// now try recurrence; safe for unbounded RRULE
	return rrule_intersect_helper(min, max, data.rrule, data.duration)
}

func parseDuration(val string) (dur time.Duration, err error) {
	var minus bool
	var seconds int64
	if val[0] == '-' {
		minus = true
	}
	val = strings.Trim(val, "-+PT")
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

func parseJournal(comp *ical.Component, timezone *time.Location) (data *compData, err error) {
	data = &compData{}

	// get UID
	if val := comp.Props.Get(ical.PropUID); val != nil {
		data.uid = val.Value
	} else {
		err = fmt.Errorf("parse error")
		return
	}

	// Journals cannot be recurring
	if val := comp.Props.Get(ical.PropRecurrenceRule); val != nil {
		return
	} else if val := comp.Props.Get(ical.PropRecurrenceDates); val != nil {
		return
	} else if val := comp.Props.Get(ical.PropExceptionDates); val != nil {
		return
	} else if val := comp.Props.Get(ical.PropRecurrenceID); val != nil {
		return
	}

	// get DTSTART; not required
	// if there is no dtstart, it should not match any filter
	// so we can leave it unset
	if val := comp.Props.Get(ical.PropDateTimeStart); val != nil {
		if t, e := val.DateTime(timezone); e != nil {
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

	data.comp = comp
	return
}

func parseFreeBusy(comp *ical.Component, timezone *time.Location) (data *compData, err error) {
	data = &compData{}

	// get UID
	if val := comp.Props.Get(ical.PropUID); val != nil {
		data.uid = val.Value
	} else {
		err = fmt.Errorf("parse error")
		return
	}

	// VFREEBUSY cannot be recurring
	if val := comp.Props.Get(ical.PropRecurrenceRule); val != nil {
		return
	} else if val := comp.Props.Get(ical.PropRecurrenceDates); val != nil {
		return
	} else if val := comp.Props.Get(ical.PropExceptionDates); val != nil {
		return
	} else if val := comp.Props.Get(ical.PropRecurrenceID); val != nil {
		return
	}

	if val_start := comp.Props.Get(ical.PropDateTimeStart); val_start == nil {
		//
	} else if val_end := comp.Props.Get(ical.PropDateTimeEnd); val_end == nil {
		//
	} else {
		// both DTSTART and DTEND, so this should be used for matching time.
		if t, e := val_start.DateTime(timezone); e != nil {
			err = e
			return
		} else {
			data.dtstart = t
		}
		if t, e := val_end.DateTime(timezone); e != nil {
			err = e
			return
		} else {
			data.duration = t.Sub(data.dtstart)
		}
	}

	if data.dtstart.IsZero() {
		// need to get free busy periods to determine matching
		data.freebusy = make([]Period, 0, 32)
		for _, fb := range comp.Props.Values(ical.PropFreeBusy) {
			if periods, e := parseFreeBusyPeriod(fb); e != nil {
				err = e
				return
			} else {
				data.freebusy = append(data.freebusy, periods...)
			}
		}
	}

	data.comp = comp
	return
}

// should check if the output has an empty value string
func filterFreeBusyPeriod(p *ical.Prop, min time.Time, max time.Time) (err error) {
	raw_periods := strings.Split(p.Value, ",")
	new_value := bytes.NewBuffer(nil)
	for _, raw_period := range raw_periods {
		if start, end, found := strings.Cut(raw_period, "/"); !found {
			err = fmt.Errorf("invalid period value")
			return
		} else if st, e := time.Parse(dateWithUTCTimeFormat, start); e != nil {
			err = e
			return
		} else {
			var dur time.Duration
			switch strings.HasPrefix(end, "P") {
			case true:
				if d, e := parseDuration(end); e != nil {
					err = e
					return
				} else {
					dur = d
				}
			case false:
				if et, e := time.Parse(dateWithUTCTimeFormat, end); e != nil {
					err = e
					return
				} else {
					dur = et.Sub(st)
				}
			}
			if st.Before(max) && st.Add(dur).After(min) {
				if new_value.Len() != 0 {
					new_value.WriteByte(',')
				}
				new_value.WriteString(raw_period)
			}
		}
	}
	p.Value = new_value.String()
	return
}

func FBQueryObject(cal *ical.Calendar, location *time.Location, fbquery *FBQuery, periods_in []Period) (periods_out []Period, err error) {
	for _, c := range cal.Children {
		switch c.Name {
		case ical.CompJournal, ical.CompToDo:
			periods_out = periods_in
			return
		case ical.CompEvent:
			if ps, e := eventToFreeBusyPeriods(cal, location, fbquery.TimeRange.start, fbquery.TimeRange.end); e != nil {
				err = e
			} else {
				periods_out = append(periods_in, ps...)
			}
			return
		case ical.CompFreeBusy:
			if ps, e := freebusyToFreeBusyPeriods(c, fbquery.TimeRange.start, fbquery.TimeRange.end); e != nil {
				err = e
			} else {
				periods_out = append(periods_in, ps...)
			}
			return
		}
	}
	return
}

func eventToFreeBusyPeriods(cal *ical.Calendar, location *time.Location, start time.Time, end time.Time) (periods []Period, err error) {
	// receive the full calendar to handle master + rescheds
	var master *compData
	var rescheds []*compData
	var exdates []time.Time

	if md, e := ParseCalendarObjectResource(cal, location); e != nil {
		err = e
		return
	} else {
		exdates = md.exdates
		rescheds = make([]*compData, 0, len(md.comps)-1)
		for _, c := range md.comps {
			if c.recurrenceid.IsZero() {
				master = &c
			} else if c.Intersect(start, end) {
				rescheds = append(rescheds, &c)
			}
		}
	}

	if master.rrule == nil {
		if master.dtstart.Before(end) && master.dtstart.Add(master.duration).After(start) && master.duration != 0 {
			return []Period{{start: master.dtstart, duration: master.duration}}, nil
		} else {
			return nil, nil
		}
	}

	periods = make([]Period, 0, 16)
	next := master.rrule.Iterator()

	// need to sort to have proper popping of passed recurrence events
	var pop_index int
	sort.Slice(rescheds, func(i int, j int) bool {
		return rescheds[i].recurrenceid.Before(rescheds[j].recurrenceid)
	})

	t, ok := next()

	for {
		if !ok {
			return
		}

		for _, s := range exdates {
			if s.Equal(t) {
				goto jump
			}
		}

		for k, c := range rescheds {
			if c.recurrenceid.Equal(t) {
				periods = append(periods, Period{c.dtstart, c.duration})
				goto jump
			} else if c.recurrenceid.Before(t) {
				// we are passed the recurrence id so pop it
				pop_index = k + 1
			}
		}

		if pop_index == 0 {
			// do nothing
		} else if pop_index == len(rescheds) {
			rescheds = nil
		} else {
			rescheds = rescheds[pop_index:]
		}
		// reset pop_index for next round of iteration
		pop_index = 0

		if t.Add(master.duration).Before(start) {
			goto jump
		} else if t.After(end) || t.Equal(end) {
			if len(rescheds) == 0 {
				// nothing left to check
				return
			}
			goto jump
		}
		periods = append(periods, Period{t, master.duration})

	jump:
		t, ok = next()
	}

}

func freebusyToFreeBusyPeriods(c *ical.Component, start time.Time, end time.Time) (periods []Period, err error) {
	for _, fb := range c.Props.Values(ical.PropFreeBusy) {
		if e := filterFreeBusyPeriod(&fb, start, end); e != nil {
			err = e
		} else if ps, e := parseFreeBusyPeriod(fb); e != nil {
			err = e
		} else {
			periods = ps
		}
	}
	return
}

func parseFreeBusyPeriod(p ical.Prop) (periods []Period, err error) {
	if p.Value == "" {
		return nil, nil
	}
	err = fmt.Errorf("invalid period")
	raw_periods := strings.Split(p.Value, ",")
	periods = make([]Period, len(raw_periods))
	for k, raw_period := range raw_periods {
		if start, end, found := strings.Cut(raw_period, "/"); !found {
			return
		} else if st, e := time.Parse(dateWithUTCTimeFormat, start); e != nil {
			err = e
			return
		} else {
			var dur time.Duration
			switch strings.HasPrefix(end, "P") {
			case true:
				if d, e := parseDuration(end); e != nil {
					err = e
					return
				} else {
					dur = d
				}
			case false:
				if et, e := time.Parse(dateWithUTCTimeFormat, end); e != nil {
					err = e
					return
				} else {
					dur = et.Sub(st)
				}
			}
			if dur <= 0 {
				return
			}
			periods[k] = Period{start: st, duration: dur}
		}
	}
	err = nil
	return
}

func parseEvent(comp *ical.Component, timezone *time.Location) (data *compData, err error) {
	data = &compData{}
	err = fmt.Errorf("parse error")

	// get uid
	if val := comp.Props.Get(ical.PropUID); val != nil {
		data.uid = val.Value
	} else {
		return
	}

	if val := comp.Props.Get(ical.PropDateTimeStart); val != nil {
		if t, e := val.DateTime(timezone); e != nil {
			err = e
			return
		} else {
			data.dtstart = t
			data.start_name = ical.PropDateTimeStart
		}
	} else {
		// need DTSTART
		return
	}

	// get duration
	if val := comp.Props.Get(ical.PropDuration); val != nil {
		if d, e := parseDuration(val.Value); e != nil {
			err = e
			return
		} else {
			data.duration = d
			data.end_name = ical.PropDuration
		}
	} else if val := comp.Props.Get(ical.PropDateTimeEnd); val != nil {
		if t, e := val.DateTime(timezone); e != nil {
			err = e
			return
		} else {
			data.duration = t.Sub(data.dtstart)
			data.end_name = ical.PropDateTimeEnd
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
		if t, e := val.DateTime(timezone); e != nil {
			err = e
			return
		} else {
			data.recurrenceid = t
		}
	}

	// recurrence rule
	if val := comp.Props.Get(ical.PropRecurrenceDates); val != nil {
		// do not allow; android calendar cannot parse these events
		return
	}

	if val := comp.Props.Get(ical.PropRecurrenceRule); val != nil {
		if r, e := rrule.StrToRRule(fmt.Sprintf("%s:%s\n%s:%s",
			"DTSTART",
			data.dtstart.In(time.UTC).Format(dateWithUTCTimeFormat),
			"RRULE",
			val.Value,
		)); e != nil {
			return
		} else {
			data.rrule = r
		}
	}

	data.comp = comp
	err = nil
	return
}

func parseTodo(comp *ical.Component, timezone *time.Location) (data *compData, err error) {
	data = &compData{}
	err = fmt.Errorf("parse error")

	// get uid
	if val := comp.Props.Get(ical.PropUID); val != nil {
		data.uid = val.Value
	} else {
		return
	}

	if val := comp.Props.Get(ical.PropDateTimeStart); val != nil {
		if t, e := val.DateTime(timezone); e != nil {
			err = e
			return
		} else {
			data.dtstart = t
			data.start_name = ical.PropDateTimeStart
		}
	}

	// get due OR duration
	if val := comp.Props.Get(ical.PropDue); val != nil {
		var due time.Time
		if t, e := val.DateTime(timezone); e != nil {
			err = e
			return
		} else {
			due = t
		}
		if data.dtstart.IsZero() {
			data.dtstart = due
			data.start_name = ical.PropDue
		} else {
			data.duration = due.Sub(data.dtstart)
			data.end_name = ical.PropDue
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
			data.end_name = ical.PropDuration
		}
	}

	if !data.dtstart.IsZero() {
		// potentially an rrule
		if val := comp.Props.Get(ical.PropRecurrenceDates); val != nil {
			return
		}

		if val := comp.Props.Get(ical.PropRecurrenceRule); val != nil {
			if r, e := rrule.StrToRRule(fmt.Sprintf("%s:%s\n%s:%s",
				"DTSTART",
				data.dtstart.In(time.UTC).Format(dateWithUTCTimeFormat),
				"RRULE",
				val.Value,
			)); e != nil {
				return
			} else {
				data.rrule = r
			}
		}
	} else {
		// dtstart was not set yet; assume completed/created handling
		var created, completed time.Time
		if val := comp.Props.Get(ical.PropCompleted); val != nil {
			if t, e := val.DateTime(timezone); e != nil {
				err = e
				return
			} else {
				completed = t
			}
		}
		if val := comp.Props.Get(ical.PropCreated); val != nil {
			if t, e := val.DateTime(timezone); e != nil {
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

	// get recurrenceid
	if val := comp.Props.Get(ical.PropRecurrenceID); val != nil {
		if t, e := val.DateTime(nil); e != nil {
			err = e
			return
		} else {
			data.recurrenceid = t
		}
	}

	data.comp = comp
	err = nil
	return
}

func parseCalendarComponent(comp *ical.Component, location *time.Location) (data *compData, err error) {
	err = &webDAVerror{
		Code:      http.StatusForbidden,
		Condition: &validCalendarObjectResourceName,
	}

	switch comp.Name {
	case ical.CompEvent:
		if edt, e := parseEvent(comp, location); e != nil {
			return
		} else {
			data = edt
		}
	case ical.CompJournal:
		if jdt, e := parseJournal(comp, location); e != nil {
			return
		} else {
			data = jdt
		}
	case ical.CompToDo:
		if tdt, e := parseTodo(comp, location); e != nil {
			return
		} else {
			data = tdt
		}
	case ical.CompFreeBusy:
		if fbdt, e := parseFreeBusy(comp, location); e != nil {
			return
		} else {
			data = fbdt
		}
	default:
		return
	}
	err = nil
	return
}

func ParseCalendarObjectResource(cal *ical.Calendar, location *time.Location) (metadata *CalendarMetaData, err error) {
	var component_type string
	var exdates []time.Time
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
		if comp, e := parseCalendarComponent(child, location); e != nil {
			err = e
			return
		} else {
			comps = append(comps, *comp)
		}
	}

	var has_master bool
	for _, c := range comps {
		// opinionated: reschedulings cannot themselves be recurring
		if c.recurrenceid.IsZero() {
			if has_master {
				// opinionated: only allow one master
				return
			} else {
				has_master = true
				if exd, e := parseExDates(c.comp, location); e != nil {
					// check the master has well-formatted exdates
					return
				} else {
					exdates = exd
				}
			}
		} else if val := c.comp.Props.Get(ical.PropRecurrenceRule); val != nil {
			return
		} else if val := c.comp.Props.Get(ical.PropExceptionDates); val != nil {
			return
		} else if val := c.comp.Props.Get(ical.PropRecurrenceID); val == nil {
			return
		} else if param := val.Params.Get("RANGE"); param == "THISANDFUTURE" {
			return
		}
	}
	if !has_master {
		// opinionated: need a master
		return
	}

	metadata = &CalendarMetaData{component_type, exdates, comps}
	err = nil
	return
}

func parseExDates(comp *ical.Component, location *time.Location) (exdates []time.Time, err error) {
	exdates = make([]time.Time, 0, 8)
	err = fmt.Errorf("bad exdates")
	for _, p := range comp.Props.Values(ical.PropExceptionDates) {
		switch p.ValueType() {
		case ical.ValueDateTime:
			if tzid := p.Params.Get(ical.ParamTimezoneID); tzid != "" {
				if l, e := time.LoadLocation(tzid); e == nil {
					location = l
				}
			}
			for _, s := range strings.Split(p.Value, ",") {
				if len(s) == len(dateWithUTCTimeFormat) {
					if t, e := time.ParseInLocation(dateWithUTCTimeFormat, s, time.UTC); e == nil {
						exdates = append(exdates, t)
					} else {
						return
					}
				} else {
					if t, e := time.ParseInLocation(dateTimeFormat, s, location); e == nil {
						exdates = append(exdates, t)
					} else {
						return
					}
				}
			}
		case ical.ValueDate:
			for _, s := range strings.Split(p.Value, ",") {
				if t, e := time.ParseInLocation(dateFormat, s, location); e == nil {
					exdates = append(exdates, t)
				} else {
					return
				}
			}
		}
	}
	err = nil
	return
}

func DoesAlarmIntersect(alarm *ical.Component, parent *ical.Component, location *time.Location, start time.Time, end time.Time) (yes bool, err error) {
	err = fmt.Errorf("invalid alarm")
	var alarm_repeat uint64 = 0
	if p := alarm.Props.Get(ical.PropRepeat); p == nil {
		//
	} else if d, e := strconv.ParseUint(p.Value, 10, 64); e != nil {
		return
	} else {
		alarm_repeat = d
	}

	var alarm_duration time.Duration = 0
	if p := alarm.Props.Get(ical.PropDuration); p == nil {
		//
	} else if d, e := parseDuration(p.Value); e != nil {
		return
	} else {
		alarm_duration = d
	}

	var parent_data *compData
	if p := alarm.Props.Get(ical.PropTrigger); p == nil {
		return
	} else if pd, e := parseCalendarComponent(parent, location); e != nil {
		return
	} else {
		parent_data = pd
		switch p.ValueType() {
		case ical.ValueDuration:
			var duration time.Duration
			if d, e := parseDuration(p.Value); e != nil {
				return
			} else {
				duration = d
			}
			var reltype string = "START"
			if rl := p.Params.Get(ical.ParamRelated); rl != "" {
				reltype = rl
			}
			switch reltype {
			case "START":
				parent_data.dtstart = parent_data.dtstart.Add(duration)
			case "END":
				parent_data.dtstart = parent_data.dtstart.Add(parent_data.duration).Add(duration)
			default:
				return
			}
			parent_data.duration = 0
		case ical.ValueDateTime:
			if t, e := p.DateTime(location); e != nil {
				return
			} else {
				parent_data.dtstart = t
				parent_data.duration = 0
			}
		}
	}

	var i uint64 = 0

	if alarm_repeat > 12 {
		alarm_repeat = 12
	}

	for {
		if ok := parent_data.Intersect(start, end); ok {
			return true, nil
		}

		if alarm_duration == 0 {
			return false, nil
		}

		if i < alarm_repeat {
			parent_data.dtstart = parent_data.dtstart.Add(alarm_duration)
			i++
			continue
		}
		return false, nil
	}
}
