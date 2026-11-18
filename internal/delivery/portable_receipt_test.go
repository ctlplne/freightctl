package delivery

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestPortableReceiptUsesOnlyTheOriginalProtocolObservation(t *testing.T) {
	for _, test := range []struct {
		protocol string
		ftps     *FTPSDefinition
		dav      *DAVDefinition
		build    func(*store.Delivery, *Definition, bool) json.RawMessage
	}{
		{"sftp", nil, nil, receipt},
		{"ftps", &FTPSDefinition{}, nil, ftpsReceipt},
		{"webdav", nil, &DAVDefinition{}, davReceipt},
	} {
		t.Run(test.protocol, func(t *testing.T) {
			d := &store.Delivery{State: "succeeded"}
			spec := &Definition{Directory: "/proof", Filename: "file", Source: store.File{Size: 42}, FTPS: test.ftps, DAV: test.dav}
			for _, reconciled := range []bool{false, true} {
				d.Observation = test.build(d, spec, reconciled)
				protocol, result, err := canonicalPortableObservation(d, spec)
				if err != nil || protocol != test.protocol || !bytes.Equal(result, d.Observation) ||
					!bytes.Contains(result, []byte(`"business_acceptance":"unknown"`)) {
					t.Fatal("portable receipt changed the original observation", err)
				}
				extra := append([]byte(`{"unrecognized_credential_reference":"/protected/file",`), d.Observation[1:]...)
				d.Observation = extra
				if _, _, err := canonicalPortableObservation(d, spec); !errors.Is(err, store.ErrState) {
					t.Fatal("portable receipt accepted an unknown stored field", err)
				}
			}
		})
	}
}
