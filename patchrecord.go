package gips

import "errors"

// PatchRecord is a record of the offset and data that is to be written to a
// binary file.
type PatchRecord struct {
	isrle  bool
	size   uint16
	offset []byte
	data   []byte
}

// Validate the PatchRecord by making sure that its size, and match what is set
// for PatchRecord.isrle
func (pr *PatchRecord) Validate() error {
	if string(pr.offset) == ipsEOF {
		return errors.New("Offset is EOF")
	}

	if pr.isrle {
		if len(pr.data) > 1 {
			return errors.New("Extra data present for RLE record")
		}
	}

	if pr.size < 1 {
		return errors.New("Size is 0")
	}

	return nil
}

// NewPatchRecord returns a new PatchRecord or an error
func NewPatchRecord(o []byte, s uint16, d []byte, r bool) (*PatchRecord, error) {
	if len(o) != 3 {
		return nil, errors.New("Invalid size offset given")
	}

	if string(o) == ipsEOF {
		return nil, errors.New("EOF provided")
	}

	return &PatchRecord{
		isrle:  r,
		offset: o,
		size:   s,
		data:   d,
	}, nil
}
