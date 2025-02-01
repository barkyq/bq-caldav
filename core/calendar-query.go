package core

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/emersion/go-ical"
)

func CheckCalendarQueryFilterIsValid(query *Query) (err error) {
	err = &webDAVerror{
		Code:      http.StatusForbidden,
		Condition: &validFilterName,
	}

	if query.CalendarFilter == nil {
		return
	} else if query.CalendarFilter.CompFilter.Name != ical.CompCalendar {
		// toplevel needs to be VCALENDAR
		return
	}
	for _, cf := range query.CalendarFilter.CompFilter.CompFilters {
		if cf.IsNotDefined != nil {
			continue
		}
		// TODO: check props
		switch cf.Name {
		case ical.CompEvent, ical.CompToDo:
			var seen_alarm bool
			for _, cf := range cf.CompFilters {
				if cf.Name != ical.CompAlarm {
					return
				} else if seen_alarm {
					return
				} else {
					seen_alarm = true
				}
			}
		case ical.CompTimezone:
			var seen_daylight, seen_standard bool
			for _, cf := range cf.CompFilters {
				switch cf.Name {
				case ical.CompTimezoneDaylight:
					if seen_daylight {
						return
					} else {
						seen_daylight = true
					}
				case ical.CompTimezoneStandard:
					if seen_standard {
						return
					} else {
						seen_standard = true
					}
				}
			}
		case ical.CompJournal:
			if cf.CompFilters != nil {
				return
			}
		default:
		}
	}

	err = nil
	return
}

func MatchCalendarWithQuery(cal *ical.Calendar, query *Query) (bool, error) {
	if ok, e := matchCompFilterWithComp(query.CalendarFilter.CompFilter, cal.Component, query.Timezone.Location); e != nil {
		return false, &webDAVerror{
			Code:      http.StatusForbidden,
			Condition: &supportedFilterName,
		}
	} else {
		return ok, nil
	}
}

func matchCompFilterWithComp(cf compFilter, comp *ical.Component, location *time.Location) (match bool, err error) {
	switch {
	case cf.IsNotDefined != nil:
		return false, nil
	case cf.TimeRange != nil:
		// todo: VFREEBUSY and VALARM
		if comp.Name != ical.CompEvent && comp.Name != ical.CompToDo && comp.Name != ical.CompJournal {
			return false, fmt.Errorf("unsupported comp in compfilter")
		} else if data, e := parseCalendarComponent(comp, location); e != nil {
			return false, e
		} else if data.Intersect(cf.TimeRange.start, cf.TimeRange.end) {
			return true, nil
		} else {
			return false, nil
		}
	case cf.PropFilters != nil || cf.CompFilters != nil:
		if ok1, e := matchPropFiltersWithComp(cf.PropFilters, comp, location); e != nil {
			return false, e
		} else if ok2, e := matchCompFiltersWithCompChildren(cf.CompFilters, comp.Children, location); e != nil {
			return false, e
		} else {
			return ok1 && ok2, nil
		}
	default:
		return true, nil
	}
}

func matchPropFiltersWithComp(pfs []calendarPropFilter, comp *ical.Component, location *time.Location) (match bool, err error) {
outer:
	for _, pf := range pfs {
		values := comp.Props.Values(pf.Name)
		switch {
		case pf.IsNotDefined != nil:
			if values != nil {
				return false, nil
			}
		case pf.TimeRange != nil:
			for _, v := range values {
				if t, e := v.DateTime(location); e != nil {
					return false, e
				} else if t.After(pf.TimeRange.end) || t.Before(pf.TimeRange.start) || t.Equal(pf.TimeRange.end) {
					continue
				} else if ok, e := matchParamFiltersWithProp(pf.ParamFilter, &v); e != nil {
					return false, e
				} else if !ok {
					continue
				} else {
					continue outer
				}
			}
			return false, nil
		case pf.TextMatch != nil:
			for _, v := range values {
				if vt := v.ValueType(); vt != ical.ValueText {
					return false, fmt.Errorf("invalid value type for text-match")
				} else if !matchTextMatchWithText(pf.TextMatch, v.Value) {
					continue
				} else if ok, e := matchParamFiltersWithProp(pf.ParamFilter, &v); e != nil {
					continue
				} else if !ok {
					continue
				} else {
					continue outer
				}
			}
			return false, nil
		case pf.ParamFilter != nil:
			for _, v := range values {
				if ok, e := matchParamFiltersWithProp(pf.ParamFilter, &v); e != nil {
					return false, e
				} else if !ok {
					continue
				} else {
					continue outer
				}
			}
			return false, nil
		default:
			if values != nil {
				continue outer
			}
		}
	}
	return true, nil
}

func matchTextMatchWithText(tm *textMatch, text string) bool {
	return strings.Contains(strings.ToLower(text), tm.Text)
}

func matchParamFiltersWithProp(pfs []paramFilter, prop *ical.Prop) (ok bool, err error) {
outer:
	for _, pf := range pfs {
		values := prop.Params.Values(pf.Name)
		switch {
		case pf.IsNotDefined != nil:
			if values != nil {
				return false, nil
			}
		case pf.TextMatch != nil:
			for _, v := range values {
				if !matchTextMatchWithText(pf.TextMatch, v) {
					continue
				} else {
					continue outer
				}
			}
			return false, nil
		}
	}
	return true, nil
}

func matchCompFiltersWithCompChildren(cfs []compFilter, children []*ical.Component, location *time.Location) (match bool, err error) {
outer:
	for _, cf := range cfs {
		for _, child := range children {
			if child.Name != cf.Name {
				continue
			} else if match, err = matchCompFilterWithComp(cf, child, location); err != nil {
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
