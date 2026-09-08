package remote

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Validate server-controlled lengths before the NTLM library reads AV fields.
// The library assumes AV_FLAGS and AV_TIMESTAMP have fixed-width values.
func validateChallenge(b []byte, sealed bool) error {
	bad := errors.New("invalid NTLM type-2 challenge")
	if len(b) < 48 || len(b) > 65535 || !bytes.Equal(b[:8], []byte("NTLMSSP\x00")) || binary.LittleEndian.Uint32(b[8:12]) != 2 {
		return bad
	}
	flags := binary.LittleEndian.Uint32(b[20:24])
	if flags&0x800 != 0 {
		return errors.New("anonymous NTLM is not supported")
	}
	const required = uint32(0x20000000 | 0x00000010 | 0x00000020 | 0x00080000)
	if sealed && flags&required != required {
		return errors.New("server must negotiate NTLM 128-bit signing, sealing and extended session security")
	}
	if flags&0x02000000 != 0 && len(b) < 56 {
		return bad
	}
	for _, offset := range []int{12, 40} {
		size := uint64(binary.LittleEndian.Uint16(b[offset:]))
		start := uint64(binary.LittleEndian.Uint32(b[offset+4:]))
		if size > 0 && (start < 48 || start+size > uint64(len(b))) {
			return bad
		}
	}
	if flags&0x800000 == 0 {
		return nil
	}
	size := int(binary.LittleEndian.Uint16(b[40:]))
	start := int(binary.LittleEndian.Uint32(b[44:]))
	if size == 0 {
		return bad
	}
	data := b[start : start+size]
	seen := map[uint16]bool{}
	for len(data) >= 4 {
		id, n := binary.LittleEndian.Uint16(data), int(binary.LittleEndian.Uint16(data[2:]))
		data = data[4:]
		if n > len(data) || seen[id] {
			return bad
		}
		seen[id] = true
		if id == 0 {
			if n != 0 || len(data) != 0 {
				return bad
			}
			return nil
		}
		switch id {
		case 1, 2, 3, 4, 5, 9:
			if n%2 != 0 {
				return bad
			}
		case 6:
			if n != 4 {
				return bad
			}
		case 7:
			if n != 8 {
				return bad
			}
		case 10:
			if n != 16 {
				return bad
			}
		}
		data = data[n:]
	}
	return bad
}
