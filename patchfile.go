package gips

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
)

// PatchFile describes an IPS patch before it's applied to a file, or generated
type PatchFile struct {
	records  []*PatchRecord
	truncate uint16
}

var bToU16 = binary.BigEndian.Uint16

// Write the PatchFile to a file
func (pf *PatchFile) Write(f *os.File) error {
	f.Seek(0, 0)

	if err := f.Truncate(0); err != nil {
		return err
	}

	f.WriteString(ipsHeader)
	for _, pr := range pf.records {
		pr.Write(f)
	}
	f.WriteString(ipsEOF)

	if pf.truncate > 0 {
		truncate := make([]byte, 3)
		binary.BigEndian.PutUint16(truncate, pf.truncate)
		f.Write(truncate)
	}

	return nil
}

// Apply the PatchFile definition to an open file
func (pf *PatchFile) Apply(f *os.File) error {
	f.Seek(0, 0)
	for _, p := range pf.records {
		offset := int64(bToU16(p.offset))
		if !p.isRLE {
			if _, err := f.WriteAt(p.data, offset); err != nil {
				return err
			}
		} else {
			f.Seek(offset, 0)
			for i := 0; i <= int(p.size); i++ {
				if _, err := f.Write(p.data); err != nil {
					return err
				}
			}
		}
	}

	if pf.truncate > 0 {
		if err := f.Truncate(int64(pf.truncate)); err != nil {
			return err
		}
	}

	return nil
}

// ProcessPatchFile processes a given ips patch file, and returns an object that
// describes its records
func ProcessPatchFile(path string) (*PatchFile, error) {
	ips := &PatchFile{
		records:  make([]*PatchRecord, 0),
		truncate: 0,
	}

	header := make([]byte, 5)

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	_, err = f.Read(header)
	if err != nil {
		log.Fatal(err)
	}

	if string(header) != ipsHeader {
		log.Fatal(errors.New("Patch is not valid. Invalid header"))
	}

	for {
		var data []byte
		offset := make([]byte, 3)
		sizeb := make([]byte, 2)
		rle := false

		_, err := f.Read(offset)
		if err != nil {
			return nil, errors.New("Finished read before EOF was found")
		}

		if string(offset) == ipsEOF {
			break
		}

		_, err = f.Read(sizeb)
		if err != nil {
			log.Fatal(err)
		}

		size := bToU16(sizeb)

		if size == 0 {
			// Detect and implement RLE
			rle = true
			sizeb = make([]byte, 2)
			_, err = f.Read(sizeb)
			if err != nil {
				log.Fatal(err)
			}
			size = bToU16(sizeb)
			data = make([]byte, 1)
		} else {
			// Or just setup the data slice
			data = make([]byte, size)
		}

		f.Read(data)
		r, err := NewPatchRecord(offset, size, data, rle)
		if err != nil {
			return nil, err
		}

		ips.records = append(ips.records, r)
	}

	// Implement the IPS truncate extension
	truncb := make([]byte, 64)
	_, err = f.Read(truncb)
	if err == nil {
		ips.truncate = binary.BigEndian.Uint16(truncb)
	}

	// Check for file EOF and make sure the eof byte that we received wasn't
	// just a NUL
	eof := make([]byte, 3)
	_, err = f.Read(eof)
	if err != nil {
		if eof[0] != 0 && len(eof) == 1 {
			return nil, errors.New("Invalid patch provided. Data found past EOF: " +
				fmt.Sprintf("[% x]", eof))
		}
	}

	return ips, nil
}
