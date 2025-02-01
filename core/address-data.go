package core

import (
	"bytes"
	"encoding/xml"
	"net/http"

	"github.com/emersion/go-vcard"
)

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
