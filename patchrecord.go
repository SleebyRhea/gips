package gips

import (
	"encoding/binary"
	"errors"
	"os"
)

// PatchRecord is a record of the offset and data that is to be written to a
// binary file.
type PatchRecord struct {
	isRLE  bool
	size   uint16
	offset []byte
	data   []byte
}

// Validate the PatchRecord by making sure that its size, and match what is set
// for PatchRecord.isRLE
func (pr *PatchRecord) Validate() error {
	if string(pr.offset) == ipsEOF {
		return errors.New("Offset is EOF")
	}

	if pr.isRLE {
		if len(pr.data) > 1 {
			return errors.New("Extra data present for RLE record")
		}
	}

	if pr.size < 1 {
		return errors.New("Size is 0")
	}

	return nil
}

// Write the PatchRecord to the file descriptor
func (pr *PatchRecord) Write(f *os.File) error {
	bytes := make([][]byte, 0)
	size := make([]byte, 2)
	binary.BigEndian.PutUint16(size, pr.size)

	bytes = append(bytes, pr.offset)
	if pr.isRLE {
		bytes = append(bytes, []byte{0, 0})
	}
	bytes = append(bytes, size, pr.data)

	for _, b := range bytes {
		if _, err := f.Write(b); err != nil {
			return err
		}
	}

	return nil
}

// Apply a PatchRecord to the file descriptor
// func (pr *PatchRecord) Apply(f *os.File) error {
// }

// NewPatchRecord returns a new PatchRecord or an error
func NewPatchRecord(o []byte, s uint16, d []byte, r bool) (*PatchRecord, error) {
	if len(o) != 3 {
		return nil, errors.New("Invalid size offset given")
	}

	if string(o) == ipsEOF {
		return nil, errors.New("EOF provided")
	}

	return &PatchRecord{
		isRLE:  r,
		offset: o,
		size:   s,
		data:   d,
	}, nil
}
