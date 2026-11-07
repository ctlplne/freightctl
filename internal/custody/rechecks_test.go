package custody

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

func TestRecheckInterruptedReadRetainsItsReservedPartialObject(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "custody"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	name := Name(secure.NewID(), secure.NewID(), secure.NewID())
	denied := errors.New("authority changed during copy")
	calls := 0
	reader := recheckReader{ctx: t.Context(), source: strings.NewReader(strings.Repeat("x", 65536)), check: func() error {
		calls++
		if calls > 1 {
			return denied
		}
		return nil
	}}
	if err = d.stage(name, reader, 65536, secure.Digest([]byte(strings.Repeat("x", 65536))), true); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	st, err := d.root.Stat(name)
	if err != nil || st.Size() != 32768 {
		t.Fatal(st, err)
	}
	requireObjectProtectionForTest(t, filepath.Join(d.root.Name(), name), protectedfs.PrivateWritable)
	f, err := d.root.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(b) != strings.Repeat("x", 32768) {
		t.Fatal(err)
	}
	if err = d.stage(name, strings.NewReader("replacement"), 11, secure.Digest([]byte("replacement")), true); !errors.Is(err, os.ErrExist) {
		t.Fatal("reserved partial overwritten", err)
	}
}
