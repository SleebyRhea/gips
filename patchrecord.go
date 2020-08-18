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

// Validate the PatchRecord by making sure that its size, and data match what is
// set for PatchRecord.isRLE
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

	if len(pr.data) != int(pr.size) {
		return errors.New("Size does not match data")
	}

	return nil
}

// Bytes returns the byte data that this PatchRecord represents
func (pr *PatchRecord) Bytes() []byte {
	data := make([]byte, 0)
	size := make([]byte, 2)
	binary.BigEndian.PutUint16(size, pr.size)

	data = append(data, pr.offset...)
	if pr.isRLE {
		data = append(data, []byte{0, 0}...)
	}
	data = append(data, size...)
	data = append(data, pr.data...)
	return data
}

// Write the PatchRecord to the file descriptor
func (pr *PatchRecord) Write(f *os.File) error {
	logByteWrite(f, pr)

	if err := pr.Validate(); err != nil {
		return err
	}

	if _, err := f.Write(pr.Bytes()); err != nil {
		return err
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
