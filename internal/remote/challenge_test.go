package remote

import (
	"encoding/binary"
	"github.com/bodgit/ntlmssp"
	"testing"
)

func type2(flags uint32, av []byte) []byte {
	b := make([]byte, 48+len(av))
	copy(b, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:], 2)
	binary.LittleEndian.PutUint32(b[20:], flags)
	binary.LittleEndian.PutUint16(b[40:], uint16(len(av)))
	binary.LittleEndian.PutUint16(b[42:], uint16(len(av)))
	binary.LittleEndian.PutUint32(b[44:], 48)
	copy(b[48:], av)
	return b
}

func TestValidateChallenge(t *testing.T) {
	const flags = uint32(0x20080031)
	for _, tt := range []struct {
		name string
		b    []byte
		fail bool
	}{
		{"valid", type2(flags, nil), false},
		{"weak key", type2(flags&^0x20000000, nil), true},
		{"anonymous", type2(flags|0x800, nil), true},
		{"missing ESS", type2(flags&^0x80000, nil), true},
		{"truncated", []byte("NTLMSSP"), true},
		{"short AV flags", type2(flags|0x800000, []byte{7, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 1, 0, 0, 0, 0, 0, 0}), true},
		{"short timestamp", type2(flags|0x800000, []byte{7, 0, 1, 0, 0, 0, 0, 0, 0}), true},
		{"missing terminator", type2(flags|0x800000, []byte{6, 0, 4, 0, 0, 0, 0, 0}), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateChallenge(tt.b, true); (err != nil) != tt.fail {
				t.Fatalf("got error=%v fail=%v", err, tt.fail)
			}
		})
	}
}

func FuzzChallenge(f *testing.F) {
	f.Add(type2(0x20880031, []byte{0, 0, 0, 0}))
	f.Add([]byte("bad"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if err := validateChallenge(b, true); err != nil {
			return
		}
		c, err := ntlmssp.NewClient(ntlmssp.SetUserInfo("alice", "test-secret"))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Authenticate(nil, nil)
		_, _ = c.Authenticate(b, nil)
	})
}
