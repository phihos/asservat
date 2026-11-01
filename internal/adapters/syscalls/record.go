package syscalls

import (
	"encoding/binary"
	"errors"
)

// RecordSize is the fixed ring record of one Call (little endian):
//
//	off  size  field
//	  0     1  status (1..4)
//	  1     1  reserved, zero
//	  2     2  syscall number
//	  4     4  pid
//	  8     8  entered boot ns
//	 16     8  exited boot ns
//	 24     8  ret
const RecordSize = 32

// ErrRecord rejects a malformed ring record.
var ErrRecord = errors.New("syscalls: invalid call record")

// AppendRecord appends c's fixed record to b.
func AppendRecord(b []byte, c Call) []byte {
	le := binary.LittleEndian
	b = append(b, byte(c.Status), 0)
	b = le.AppendUint16(b, c.Number)
	b = le.AppendUint32(b, c.PID)
	b = le.AppendUint64(b, c.EnteredBoot)
	b = le.AppendUint64(b, c.ExitedBoot)
	return le.AppendUint64(b, uint64(c.Ret))
}

// MarshalRecord returns c's fixed record.
func MarshalRecord(c Call) []byte { return AppendRecord(make([]byte, 0, RecordSize), c) }

// UnmarshalRecord decodes exactly one record.
func UnmarshalRecord(b []byte) (Call, error) {
	if len(b) != RecordSize || b[0] < byte(Returned) || b[0] > byte(Unmatched) || b[1] != 0 {
		return Call{}, ErrRecord
	}
	le := binary.LittleEndian
	return Call{
		Status:      Status(b[0]),
		Number:      le.Uint16(b[2:]),
		PID:         le.Uint32(b[4:]),
		EnteredBoot: le.Uint64(b[8:]),
		ExitedBoot:  le.Uint64(b[16:]),
		Ret:         int64(le.Uint64(b[24:])),
	}, nil
}
