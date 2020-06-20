package gips

import (
	"encoding/binary"
	"fmt"
	"os"
)

const (
	ipsHeader = "PATCH"
	ipsEOF    = "EOF"
)

var verbose bool

func init() {
	verbose = false
}

// SetVerbose sets the verbosity for this module
func SetVerbose(b bool) {
	verbose = b
}

func logByteWrite(f *os.File, pr *PatchRecord) {
	size := make([]byte, 2)
	binary.BigEndian.PutUint16(size, pr.size)
	if verbose {
		switch pr.isRLE {
		case false:
			fmt.Printf("REG [%x | %x | %x]\n", pr.offset, size, pr.data)
		case true:
			fmt.Printf("RLE [%x | %x | %x | %x]\n", pr.offset, []byte{0, 0},
				size, pr.data)
		default:
			panic("Incorrect number of bytes in patch slice")
		}
	}
}
