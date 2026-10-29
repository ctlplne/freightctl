package delivery

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

type stream struct{ io.Reader }

func (s stream) Write(p []byte) (int, error) { return len(p), nil }
func (s stream) Close() error                { return nil }
func TestReceiverFrameBoundsBeforeAllocation(t *testing.T) {
	for _, n := range []uint32{0, 1, 256 << 10, (256 << 10) + 1, 0xffffffff} {
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, n)
		if n <= 256<<10 {
			data = append(data, make([]byte, n)...)
		}
		bounded := &packetStream{ReadWriteCloser: stream{bytes.NewReader(data)}}
		result, err := io.ReadAll(bounded)
		if n == 0 || n > 256<<10 {
			if err == nil || len(result) != 0 {
				t.Fatal("unsafe frame reached decoder", n, len(result), err)
			}
		} else if len(result) != int(n)+4 {
			t.Fatal("valid fragmented frame", n, len(result), err)
		}
	}
}
