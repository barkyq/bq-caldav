package core

import (
	"bytes"
	"encoding/xml"
	"net/http"

	"github.com/emersion/go-vcard"
)

// Parses the request struct to extract the CalendarDataReq
// Applies to calendar-multiget and calendar-query REPORT
func ParseAddressData(request HasAddressDataProp) (*AddressDataReq, error) {
	if adata := request.getAddressData(); adata == nil {
		return nil, nil
	} else if adata.Content != nil {
		buf := bytes.NewBufferString("<address-data xmlns=\"urn:ietf:params:xml:ns:carddav\">")
		buf.Write(adata.Content)
		buf.WriteString("</address-data>")
		ad := &AddressDataReq{}
		if e := xml.NewDecoder(buf).Decode(ad); e != nil {
			return nil, &webDAVerror{
				Code:      http.StatusBadRequest,
				Condition: &addressDataName,
			}
		} else {
			return ad, nil
		}
	} else {
		return &AddressDataReq{}, nil
	}
}

func cardPartialRetrieval(card vcard.Card, props []propReq) (new_card vcard.Card) {
	new_card = make(vcard.Card)
	props = append(props, propReq{Name: vcard.FieldFormattedName})
	for _, prop := range props {
		if _, ok := new_card[prop.Name]; ok {
			continue
		} else if fs, ok := card[prop.Name]; !ok {
			continue
		} else if prop.NoValue {
			new_card[prop.Name] = []*vcard.Field{{Value: ""}}
		} else {
			new_card[prop.Name] = fs
		}
	}
	vcard.ToV4(new_card)
	return new_card
}

func AddressData(card vcard.Card, ad *AddressDataReq) (*Any, error) {
	if ad == nil {
		return nil, nil
	}

	if props := ad.Props; props != nil {
		// partial retrieval
		card = cardPartialRetrieval(card, props)
	} else {
		vcard.ToV4(card)
	}

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
