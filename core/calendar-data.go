package core

import (
	"bytes"
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/emersion/go-ical"
	"github.com/teambition/rrule-go"
)

// Parses the request struct to extract the CalendarDataReq
// Applies to calendar-multiget and calendar-query REPORT
func ParseCalendarData(request HasCalendarDataProp) (*CalendarDataReq, error) {
	if cdata := request.getCalendarData(); cdata == nil {
		return nil, nil
	} else if cdata.Content != nil {
		buf := bytes.NewBufferString("<calendar-data xmlns=\"urn:ietf:params:xml:ns:caldav\">")
		buf.Write(cdata.Content)
		buf.WriteString("</calendar-data>")
		cd := &CalendarDataReq{}
		if e := xml.NewDecoder(buf).Decode(cd); e != nil {
			return nil, &webDAVerror{
				Code:      http.StatusBadRequest,
				Condition: &calendarDataName,
			}
		} else if e := cd.checkCalendarDataReq(); e != nil {
			return nil, e
		} else {
			return cd, nil
		}
	} else {
		return &CalendarDataReq{}, nil
	}
}

func (cd *CalendarDataReq) checkCalendarDataReq() (err error) {
	err = &webDAVerror{
		Code:      http.StatusBadRequest,
		Condition: &validCalendarDataName,
	}
	if cd.Expand != nil && cd.LimitRecurrenceSet != nil {
		return
	} else if exp := cd.Expand; exp != nil && (exp.start.IsZero() || !exp.end.After(exp.start)) {
		return
	} else if lrs := cd.LimitRecurrenceSet; lrs != nil && (lrs.start.IsZero() || !lrs.end.After(lrs.start)) {
		return
	} else if lfbs := cd.LimitFreeBusySet; lfbs != nil && (lfbs.start.IsZero() || !lfbs.end.After(lfbs.start)) {
		return
	} else if cd.CompReq == nil {
		// nothing else to check
	} else if e := cd.CompReq.checkCompReq(); e != nil {
		return
	} else if cd.CompReq.Name != ical.CompCalendar {
		return
	} else if e := checkPropReqRepetitions(cd.CompReq.Props); e != nil {
		return
	} else {
		var event_seen, todo_seen, journal_seen, timezone_seen bool
		for _, cr := range cd.CompReq.Comps {
			if e := cr.checkCompReq(); e != nil {
				return
			}
			switch cr.Name {
			case ical.CompEvent:
				if event_seen {
					return
				}
				event_seen = true
			case ical.CompToDo:
				if todo_seen {
					return
				}
				todo_seen = true
			case ical.CompJournal:
				if journal_seen {
					return
				}
				journal_seen = true
			case ical.CompTimezone:
				if timezone_seen {
					return
				}
				timezone_seen = true
			}
		}
	}
	err = nil
	return
}

func (c *compReq) checkCompReq() (err error) {
	err = fmt.Errorf("bad comp req")
	if c.Allprop != nil && c.Props != nil {
		return
	} else if c.Allcomp != nil && c.Comps != nil {
		return
	} else if c.Props != nil {
		if e := checkPropReqRepetitions(c.Props); e != nil {
			return
		}
	}
	switch c.Name {
	case ical.CompJournal, ical.CompTimezone, ical.CompAlarm:
		if c.Comps != nil {
			return
		}
	case ical.CompEvent, ical.CompToDo:
		if c.Comps != nil {
			if len(c.Comps) != 1 {
				return
			} else if cr := c.Comps[0]; cr.Name != ical.CompAlarm {
				return
			} else if e := cr.checkCompReq(); e != nil {
				return
			}
		}
	}
	err = nil
	return
}

func checkPropReqRepetitions(props []propReq) (err error) {
	err = fmt.Errorf("bad prop req")
	seen := make([]string, 0, len(props))
	for _, p := range props {
		for _, s := range seen {
			if p.Name == s {
				// cannot have repeated props
				return
			}
		}
		seen = append(seen, p.Name)
	}
	err = nil
	return
}

// Marshals the output for calendar-data
func CalendarData(cal *ical.Calendar, cd *CalendarDataReq) (*Any, error) {
	if cd == nil {
		return nil, nil
	}

	if cd.Expand == nil {
		// do nothing
	} else if c, e := expandCalendar(cal, cd.Expand); e != nil {
		return nil, e
	} else {
		cal = c
	}

	if cd.LimitRecurrenceSet == nil {
		// do nothing
	} else if c, e := limitRecurrenceSet(cal, cd.LimitRecurrenceSet); e != nil {
		return nil, e
	} else {
		cal = c
	}

	if cd.LimitFreeBusySet == nil {
		// do nothing
	} else if c, e := limitFreeBusySet(cal, cd.LimitFreeBusySet); e != nil {
		return nil, e
	} else {
		cal = c
	}

	// it is unlikely, but possible, that cal has no events after expansion
	// in this case, expandCalendar or limitRecurrenceSet should have set cal to nil
	if cal == nil {
		return emptyCalendarData(), nil
	}

	if cd.CompReq == nil {
		// do nothing
	} else if c, e := partialRetrieval(cal.Component, cd.CompReq); e != nil {
		return nil, e
	} else if c.Name != ical.CompCalendar || len(c.Children) == 0 {
		cal = nil
	} else {
		cal = &ical.Calendar{Component: c}
	}

	// it is possible, that cal has no events after partial retrieval
	if cal == nil {
		return emptyCalendarData(), nil
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

func expandCalendar(source *ical.Calendar, expand *timeInterval) (expanded *ical.Calendar, err error) {
	for _, child := range source.Children {
		if child.Name == ical.CompJournal || child.Name == ical.CompFreeBusy {
			expanded = source
			return
		}
	}

	expanded = ical.NewCalendar()
	defer func() {
		if err != nil || len(expanded.Children) == 0 {
			expanded = nil
			return
		}
		// add the timezones
		for _, c := range source.Children {
			if c.Name == ical.CompTimezone {
				expanded.Children = append(expanded.Children, c)
			}
		}
	}()

	expanded.Props.SetText(ical.PropProductID, "-//bq-caldav//expand//EN")
	expanded.Props.SetText(ical.PropVersion, "2.0")
	if md, e := ParseCalendarObjectResource(source); e != nil {
		err = e
		return
	} else {
		var master *compData
		rescheds := make([]*compData, 0, len(md.comps))
		for _, c := range md.comps {
			if c.recurrenceid.IsZero() {
				master = &c
			} else if c.Intersect(expand.start, expand.end) {
				c.comp.Props.Del(ical.PropRecurrenceID)
				c.dtstart = c.dtstart.In(time.UTC)
				if v := c.comp.Props.Get(c.start_name); v == nil {
					err = fmt.Errorf("nil start name in recurring event!")
					return
				} else if vt := v.ValueType(); false {
					//
				} else {
					switch vt {
					case ical.ValueDate:
						c.comp.Props.SetDate(c.start_name, c.dtstart)
					case ical.ValueDateTime:
						c.comp.Props.SetDateTime(c.start_name, c.dtstart)
					}
				}
				if v := c.comp.Props.Get(master.end_name); v == nil {
					// do nothing
				} else if vt := v.ValueType(); false {
					//
				} else {
					switch vt {
					case ical.ValueDuration:
						c.comp.Props.SetText(ical.PropDuration, v.Value)
					case ical.ValueDate:
						c.comp.Props.SetDate(c.end_name, c.dtstart.Add(c.duration))
					case ical.ValueDateTime:
						c.comp.Props.SetDateTime(c.end_name, c.dtstart.Add(c.duration))
					}
				}
				rescheds = append(rescheds, &c)
			}
		}
		if master == nil {
			err = fmt.Errorf("nil master; not allowed!")
			return
		}

		master.comp.Props.Del(ical.PropRecurrenceRule)

		var next rrule.Next = func() (time.Time, bool) {
			return time.Time{}, false
		}

		// need to sort to have proper popping of passed recurrence events
		var pop_index int
		sort.Slice(rescheds, func(i int, j int) bool {
			return rescheds[i].recurrenceid.Before(rescheds[j].recurrenceid)
		})

		t := master.dtstart.In(time.UTC)
		ok := true
		if master.rrule != nil {
			next = master.rrule.Iterator()
			// pop the first time
			next()
		}

		for {
			for _, s := range md.exdates {
				if s.Equal(t) {
					goto jump
				}
			}

			for k, c := range rescheds {
				if c.recurrenceid.Equal(t) {
					c.comp.Props.SetText(ical.PropUID, newUUID())
					expanded.Children = append(expanded.Children, c.comp)
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

			if t.Add(master.duration).Before(expand.start) {
				goto jump
			} else if t.After(expand.end) || t.Equal(expand.end) {
				if len(rescheds) == 0 {
					// nothing left to check
					return
				}
				goto jump
			}

			if v := master.comp.Props.Get(master.start_name); v == nil {
				err = fmt.Errorf("nil start name in recurring event!")
				return
			} else if vt := v.ValueType(); false {
				//
			} else {
				switch vt {
				case ical.ValueDate:
					master.comp.Props.SetDate(master.start_name, t)
				case ical.ValueDateTime:
					master.comp.Props.SetDateTime(master.start_name, t)
				}
			}
			if v := master.comp.Props.Get(master.end_name); v == nil {
				// do nothing
			} else if vt := v.ValueType(); false {
				//
			} else {
				switch vt {
				case ical.ValueDuration:
					master.comp.Props.SetText(ical.PropDuration, v.Value)
				case ical.ValueDate:
					master.comp.Props.SetDate(master.end_name, t.Add(master.duration))
				case ical.ValueDateTime:
					master.comp.Props.SetDateTime(master.end_name, t.Add(master.duration))
				}
			}
			expanded.Children = append(expanded.Children, deepCopy(master.comp))
		jump:
			t, ok = next()
			if !ok {
				return
			}
		}
	}
}

// used in expand request
func newUUID() string {
	var u [16]byte
	if _, e := rand.Read(u[:]); e != nil {
		panic(e)
	}

	// Set version to 4 (random) -- 0100 in binary
	u[6] = (u[6] & 0x0f) | 0x40

	// Set variant to RFC 4122 -- 10xxxxxx
	u[8] = (u[8] & 0x3f) | 0x80

	return fmt.Sprintf("%X-%X-%X-%X-%X", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// used in expand request
func deepCopy(master *ical.Component) *ical.Component {
	new_comp := ical.NewComponent(master.Name)
	propmap := map[string][]ical.Prop(master.Props)
	for _, v := range propmap {
		for _, p := range v {
			new_comp.Props.Add(&p)
		}
	}
	new_comp.Props.SetText(ical.PropUID, newUUID())
	return new_comp
}

func limitFreeBusySet(source *ical.Calendar, limit_freebusy_set *timeInterval) (limited *ical.Calendar, err error) {
	for _, child := range source.Children {
		if child.Name == ical.CompFreeBusy {
			old_props := child.Props.Values(ical.PropFreeBusy)
			new_props := make([]ical.Prop, 0, len(old_props))
			for _, v := range old_props {
				if e := filterFreeBusyPeriod(&v, limit_freebusy_set.start, limit_freebusy_set.end); e != nil {
					err = e
					return
				} else if v.Value != "" {
					new_props = append(new_props, v)
				}
			}
			child.Props[ical.PropFreeBusy] = new_props
		}
	}
	return source, nil
}

func limitRecurrenceSet(source *ical.Calendar, limit_recurrence_set *timeInterval) (limited *ical.Calendar, err error) {
	for _, child := range source.Children {
		if child.Name == ical.CompJournal || child.Name == ical.CompFreeBusy {
			limited = source
			return
		}
	}

	limited = ical.NewCalendar()
	defer func() {
		if err != nil {
			limited = nil
			return
		}
		// add the timezones
		for _, c := range source.Children {
			if c.Name == ical.CompTimezone {
				limited.Children = append(limited.Children, c)
			}
		}
	}()

	limited.Props.SetText(ical.PropProductID, "-//bq-caldav//limit-recurrence-set//EN")
	limited.Props.SetText(ical.PropVersion, "2.0")

	if md, e := ParseCalendarObjectResource(source); e != nil {
		err = e
		return
	} else {
		for _, c := range md.comps {
			if c.recurrenceid.IsZero() {
				limited.Children = append(limited.Children, c.comp)
			} else if c.Intersect(limit_recurrence_set.start, limit_recurrence_set.end) {
				// add because it intersects
				limited.Children = append(limited.Children, c.comp)
			}
		}
	}
	return
}

func partialRetrieval(source *ical.Component, compReq *compReq) (partial *ical.Component, err error) {
	if source.Name != compReq.Name {
		return
	}

	if source.Name == ical.CompCalendar {
		source.Props.SetText(ical.PropProductID, "-//bq-caldav//partial-retrieval//EN")
	}

	partial = ical.NewComponent(source.Name)
	var required []string

	if compReq.Allprop != nil {
		partial.Props = source.Props
		goto jump1
	}

	// need to do this, even though CalDAV RFC allows absence of required properties
	// because go-ical will not encode if required properties are missing.
	switch source.Name {
	case ical.CompCalendar:
		required = []string{ical.PropVersion, ical.PropProductID}
	case ical.CompEvent:
		required = []string{ical.PropUID, ical.PropDateTimeStamp, ical.PropDateTimeStart}
	case ical.CompToDo, ical.CompJournal, ical.CompFreeBusy:
		required = []string{ical.PropUID, ical.PropDateTimeStamp}
	case ical.CompTimezone:
		required = []string{ical.PropTimezoneID}
	case ical.CompAlarm:
		required = []string{ical.PropAction, ical.PropTrigger, ical.PropDescription, ical.PropSummary}
	}

	for _, requiredp := range required {
		if p := source.Props.Get(requiredp); p != nil {
			partial.Props.Add(p)
		}
	}

	for _, p := range compReq.Props {
		for _, r := range required {
			if p.Name == r {
				// already added required properties
				continue
			}
		}
		for _, a := range source.Props.Values(p.Name) {
			if p.NoValue {
				partial.Props.Add(&ical.Prop{Name: p.Name})
			} else {
				partial.Props.Add(&a)
			}
		}
	}
jump1:
	if compReq.Allcomp != nil {
		partial.Children = source.Children
		goto jump2
	}
	for _, c := range compReq.Comps {
		for _, source_child := range source.Children {
			if source_child.Name == c.Name {
				if child, e := partialRetrieval(source_child, &c); e != nil {
					return nil, e
				} else {
					partial.Children = append(partial.Children, child)
				}
			}
		}
	}

jump2:
	return partial, nil
}
