package core

import (
	"strings"

	"github.com/emersion/go-vcard"
)

// <D:response>
//        <D:href>/home/bernard/addressbook/</D:href>
//        <D:status>HTTP/1.1 507 Insufficient Storage</D:status>
//        <D:error><D:number-of-matches-within-limits/></D:error>
//        <D:responsedescription xml:lang="en">
//          Only two matching records were returned
//        </D:responsedescription>
//      </D:response>

func InsufficientStorage(href string) Response {
	status := statusHelper(507)
	return Response{
		Hrefs:  []Href{{Target: href}},
		Status: &status,
		Error:  wrapError(numberOfMatchesWithinLimitsName, nil),
	}
}

func MatchCardWithQuery(card vcard.Card, query *Query) (ok bool) {
	defer func() {
		if query.NResults == 0 || !ok {
			return
		}
		if query.NSeen < query.NResults {
			// do nothing
		} else {
			ok = false
		}
		query.NSeen++
	}()
	filter := query.AddressbookFilter
	allof := bool(filter.AllOf)
	for _, pf := range filter.PropFilter {
		if m := matchCardWithPropFilter(card, pf); !m && allof {
			// if allof is set, this will return at some point if card does not match
			return false
		} else if m && !allof {
			// if allof is not set, this will return at some point if card does match
			return true
		}
	}
	return allof
}

func matchCardWithPropFilter(card vcard.Card, pf addressbookPropFilter) (ok bool) {
	allof := bool(pf.AllOf)
	underlying := map[string][]*vcard.Field(card)

	for _, val := range underlying[pf.Name] {
		if pf.IsNotDefined != nil {
			return false
		}
		for _, tm := range pf.TextMatch {
			if m := strings.Contains(strings.ToLower(val.Value), tm.Text); !m && allof {
				return false
			} else if m && !allof {
				return true
			}
		}
		for _, paramf := range pf.ParamFilter {
			if m := matchFieldWithParamFilter(val, paramf); !m && allof {
				// if allof is set, this will return at some point if card does not match
				return false
			} else if m && !allof {
				// if allof is not set, this will return at some point if card does match
				return true
			}

		}
	}
	return allof
}

func matchFieldWithParamFilter(field *vcard.Field, pf paramFilter) (ok bool) {
	params := field.Params[pf.Name]
	for _, param := range params {
		if pf.IsNotDefined != nil {
			return false
		} else if tm := pf.TextMatch; tm != nil {
			if strings.Contains(param, tm.Text) {
				return true
			}
		} else {
			return true
		}
	}
	return false
}
