// Package pcap is used to read and write libpcap files.
package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// PcapHdr is the libpcap defined header at the top of each libpcap file.
type PcapHdr struct {
	MagicNumber  uint32 // magic number (0xa1b2c3d4)
	VersionMajor uint16 // major version number
	VersionMinor uint16 // minor version number
	Thiszone     int32  // GMT to local correction
	Sigfigs      uint32 // accuracy of timestamps
	Snaplen      uint32 // max length of captured packets, in octets
	Network      uint32 // data link type
}

// PcapRecHdr is the libpcap defined header for each packet in a libpcap file.
type PcapRecHdr struct {
	TsSec   uint32 // timestamp seconds
	TsUsec  uint32 // timestamp microseconds or nanoseconds depending on magic number
	InclLen uint32 // number of octets of packet saved in file
	OrigLen uint32 // actual length of packet
}

// PcapError
type PcapError struct {
	errorString string
}

func (pe *PcapError) Error() string {
	return pe.errorString
}

// PcapReader encapsulates all the pcap reading logic
type PcapReader struct {
	fh         io.Reader
	Header     PcapHdr
	Endian     binary.ByteOrder
	NanoSecond bool // true if PcapRecHdr.TsUsec should be interpretted as nano seconds
}

// PcapWriter encapsulates all the pcap reading logic
type PcapWriter struct {
	fh         io.Writer
	Header     PcapHdr
	Endian     binary.ByteOrder
	NanoSecond bool // true if PcapRecHdr.TsUsec should be interpretted as nano seconds
}

// pcap magic numbers
const (
	same_endian_usec_magic = 0xa1b2c3d4 // same endian as host
	swap_endian_usec_magic = 0xd4c3b2a1 // must perform endian swap
	same_endian_nsec_magic = 0xa1b23c4d // same endian as host, nano seconds
	swap_endian_nsec_magic = 0x4d3cb2a1 // must perform endian swap, nano seconds
)

// Read the pcap file header
func (pr *PcapReader) readFileHeader() (err error) {
	// read the pcap header
	buf := make([]byte, 24)
	count, err := pr.fh.Read(buf) // read pcap file header
	if err != nil {
		return err
	} else if count != len(buf) {
		return &PcapError{fmt.Sprintf("read %v file header bytes expected %v\n", count, len(buf))}
	}

	// pcap files can be encoded in either little endian or big endian
	// Most hosts will be little endian so let's go with that first.
	pr.Endian = binary.LittleEndian

	err = binary.Read(bytes.NewBuffer(buf), pr.Endian, &pr.Header)
	if err != nil {
		return err
	}
	//fmt.Printf("magic number 0x%x", pr.Header.MagicNumber)

	// determine if values need to be swapped and if using micro or nano seconds
	if pr.Header.MagicNumber == same_endian_usec_magic {
		pr.NanoSecond = false
	} else if pr.Header.MagicNumber == swap_endian_usec_magic {
		// change to big endian
		pr.Endian = binary.BigEndian
		err = binary.Read(bytes.NewBuffer(buf), pr.Endian, &pr.Header)
		if err != nil {
			return err
		}
		pr.NanoSecond = false
	} else if pr.Header.MagicNumber == same_endian_nsec_magic {
		pr.NanoSecond = true
	} else if pr.Header.MagicNumber == swap_endian_nsec_magic {
		// change to big endian
		pr.Endian = binary.BigEndian
		err = binary.Read(bytes.NewBuffer(buf), pr.Endian, &pr.Header)
		if err != nil {
			return err
		}
		pr.NanoSecond = true
	} else {
		return &PcapError{fmt.Sprintf("invalid pcap magic number 0x%x", pr.Header.MagicNumber)}
	}

	return nil
}

// Open opens a pcap file for reading.
func Reader(fh io.Reader) (pr *PcapReader, err error) {

	pr = new(PcapReader)
	pr.fh = fh

	err = pr.readFileHeader()
	if err != nil {
		return nil, err
	}
	return pr, nil
}

// Read reads the next packet from the pcap file.
// If there are no more packets it returns nil, io.EOF
func (pr *PcapReader) Read() (ts float64, pkt []byte, err error) {

	buf := make([]byte, 16)
	count, err := pr.fh.Read(buf) // read packet header

	if err != nil {
		return ts, nil, err
	} else if count != len(buf) {
		return ts, nil, &PcapError{fmt.Sprintf("read %v packet header bytes expected %v\n", count, len(buf))}
	}

	var header PcapRecHdr
	err = binary.Read(bytes.NewBuffer(buf), pr.Endian, &header)
	if err != nil {
		return ts, nil, err
	}

	pkt = make([]byte, header.InclLen)
	count, err = pr.fh.Read(pkt) // read packet bytes
	if err != nil {
		return ts, nil, err
	} else if uint32(count) != header.InclLen {
		return ts, nil, &PcapError{fmt.Sprintf("read %v packet bytes expected %v\n", count, header.InclLen)}
	}

	if pr.NanoSecond {
		ts = float64(header.TsSec) + float64(header.TsUsec)/1000000000
	} else {
		ts = float64(header.TsSec) + float64(header.TsUsec)/1000000
	}
	return ts, pkt, nil
}

// Creates a new pcap file for writing.
func Writer(fh io.Writer) (pw *PcapWriter, err error) {

	pw = new(PcapWriter)
	pw.fh = fh

	pw.Header.MagicNumber = same_endian_usec_magic
	pw.Header.VersionMajor = 2
	pw.Header.VersionMinor = 4
	pw.Header.Thiszone = 0
	pw.Header.Sigfigs = 0
	pw.Header.Snaplen = 65535
	pw.Header.Network = 1

	// pcap files can be encoded in either little endian or big endian
	// Not sure what the host endianness is. Let's assume it's little endian.
	pw.Endian = binary.LittleEndian // would prefer binary.hostEndian if it existed

	err = binary.Write(pw.fh, pw.Endian, pw.Header)
	if err != nil {
		return nil, err
	}

	return pw, nil
}

func (pw *PcapWriter) Write(ts float64, pkt []byte) (err error) {

	integer, fraction := math.Modf(ts)
	tsSec := uint32(integer)
	tsUsec := uint32(fraction * 1000000)

	header := PcapRecHdr{
		TsSec:   tsSec,
		TsUsec:  tsUsec,
		InclLen: uint32(len(pkt)),
		OrigLen: uint32(len(pkt)),
	}

	// write packet header
	err = binary.Write(pw.fh, pw.Endian, header)
	if err != nil {
		return err
	}

	// write packet bytes
	count, err := pw.fh.Write(pkt)
	if err != nil {
		return err
	} else if uint32(count) != header.InclLen {
		return &PcapError{fmt.Sprintf("wrote %v packet bytes expected %v\n", count, header.InclLen)}
	}

	return nil
}
