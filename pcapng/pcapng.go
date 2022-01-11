// Package pcap is used to read and write libpcap files.
package pcapng2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Block Types
//  const (
//  	InterfaceDescriptionBlock = 0x00000001	
//  	SimplePacketBlock         = 0x00000003	
//  	InterfaceStatisticsBlock  = 0x00000005
//  	EnhancedPacketBlock       = 0x00000006	
//  	SectionHeaderBlock        = 0x0A0D0D0A	
//  )

// SectionHeaderBlock endianness magic numbers
const (
	MagicNumber uint32 = 0x1A2B3C4D
	SwapMagicNumber    = 0x4D3C2B1A
)

type Block interface {
	// TODO maybe make endianess a parameter Bytes(endian binary.ByteOrder)
	
	Bytes() ([]byte, error)
}

type GenericBlock struct {
	Type		uint32
	TotalLength	uint32
  	Data		[]byte	// the raw bytes of the block

	// TODO options
}

func (b *GenericBlock) Bytes() ([]byte, error) {
	return b.Data, nil
}

// Block Type = 0x0A0D0D0A
type SectionBlock struct {
    GenericBlock

	ByteOrderMagic  uint32
	MajorVersion    uint16
	MinorVersion    uint16
	SectionLength   int64
}

func (b *SectionBlock) Bytes() ([]byte, error) {

	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.LittleEndian, uint32(0x0A0D0D0A)) // Block Type
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint32(28)) // Block Total Length
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint32(0x1A2B3C4D)) // Byte-Order Magic
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint16(1)) // Major Version
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint16(0)) // Minor Version
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, int64(-1)) // Section Length
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint32(28)) // Block Total Length
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Block Type = 0x00000001
type InterfaceBlock struct {
    GenericBlock

	LinkType    uint16
	SnapLen    uint32
}

func (b *InterfaceBlock) Bytes() ([]byte, error) {

	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.LittleEndian, uint32(0x00000001)) // Block Type
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint32(20)) // Block Total Length
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, b.LinkType) // Link Type
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint16(0)) // Reserved
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, b.SnapLen) // SnapLen
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint32(20)) // Block Total Length
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type EnhancedPacketBlock struct {
    GenericBlock

	InterfaceID          uint32
	TimestampHigh        uint32
	TimestampLow         uint32
	CapturedPacketLength uint32
	OriginalPacketLength uint32
    PacketData		     []byte	// the packet
}

func (b *EnhancedPacketBlock) Bytes() ([]byte, error) {

	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.LittleEndian, uint32(0x00000006)) // Block Type
	if err != nil {
		return nil, err
	}

	padding := (4 - (len(b.PacketData) & 3)) & 3
	blockTotalLength := uint32(32 + len(b.PacketData) + padding)

	err = binary.Write(buf, binary.LittleEndian, blockTotalLength) // Block Total Length
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, b.InterfaceID) // Interface ID
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, b.TimestampHigh) // Timestamp (High)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, b.TimestampLow) // Timestamp (Low)
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, uint32(len(b.PacketData))) // Captured Packet Length
	if err != nil {
		return nil, err
	}
	err = binary.Write(buf, binary.LittleEndian, b.OriginalPacketLength) // Original Packet Length
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(b.PacketData) // Packet Data
	if err != nil {
		return nil, err
	}

	for i := 0; i < padding; i++ {
		err = binary.Write(buf, binary.LittleEndian, uint8(0)) // padding
		if err != nil {
			return nil, err
		}
	}

	err = binary.Write(buf, binary.LittleEndian, blockTotalLength) // Block Total Length
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// PcapError
type PcapError struct {
	errorString string
}

func (pe *PcapError) Error() string {
	return pe.errorString
}

// PcapngReader encapsulates all the pcap reading logic
type PcapngReader struct {
	fh         io.Reader
	//Header     PcapHdr
	Endian     binary.ByteOrder
	//NanoSecond bool // true if PcapRecHdr.TsUsec should be interpretted as nano seconds
}

// Reader opens a pcap file for reading.
// It returns a PcapngReader if successful.
func Reader(fh io.Reader) (pr *PcapngReader) {

	pr = new(PcapngReader)
	pr.fh = fh
	pr.Endian = binary.LittleEndian
	return pr
}

// Read reads the next block from the pcap file.
// If there are no more packets it returns nil, io.EOF
func (pr *PcapngReader) Read() (block interface{}, err error) {
	// the minimum sized block is 12 bytes
	buf := make([]byte, 12)
	count, err := pr.fh.Read(buf) // read block type and block length

	if err != nil {
		return nil, err
	} else if count != len(buf) {
		return nil, &PcapError{fmt.Sprintf("read %v packet header bytes expected %v\n", count, len(buf))}
	}

	var blockType uint32

	err = binary.Read(bytes.NewReader(buf[0:4]), pr.Endian, &blockType)
	if err != nil {
		return nil, err
	}
//  fmt.Printf("blockType=0x%08x\n", blockType)

	var byteOrderMagic uint32

	if blockType == 0x0A0D0D0A { // SectionHeaderBlock
		// The endianness is indicated by the Section Header Block
		//var byteOrderMagic uint32
		err = binary.Read(bytes.NewReader(buf[8:12]), pr.Endian, &byteOrderMagic)
		if err != nil {
			return nil, err
		}
	//  fmt.Printf("byteOrderMagic=0x%x\n", byteOrderMagic)

		if byteOrderMagic == SwapMagicNumber {
			pr.Endian = binary.BigEndian // swap endianness
		} else if byteOrderMagic != MagicNumber {
			return nil, &PcapError{fmt.Sprintf("Bad Magic Number 0x%08x", byteOrderMagic)}
		}
	}

	var blockTotalLength uint32
	err = binary.Read(bytes.NewReader(buf[4:8]), pr.Endian, &blockTotalLength)
	if err != nil {
		return nil, err
	}
//  fmt.Printf("blockTotalLength=%v\n", blockTotalLength)

	// read the rest of the block
	if len(buf) < int(blockTotalLength) {
		grow := make([]byte, blockTotalLength)
		copy(grow, buf)
		buf = grow

		count, err = pr.fh.Read(buf[12:]) // read the rest of the block
		if err != nil {
			return nil, err
		} else if count != len(buf)-12 {
			return nil, &PcapError{fmt.Sprintf("read %v bytes expected %v\n", count, len(buf)-12)}
		}
	}

	// InterfaceDescriptionBlock = 0x00000001	
	// SimplePacketBlock         = 0x00000003	
	// InterfaceStatisticsBlock  = 0x00000005
	// EnhancedPacketBlock       = 0x00000006	
	// SectionHeaderBlock        = 0x0A0D0D0A	

	if blockType == 0x0A0D0D0A { // SectionBlock

		var majorVersion uint16
		var minorVersion uint16
		var sectionLength int64

		err = binary.Read(bytes.NewBuffer(buf[12:14]), pr.Endian, &majorVersion)
		if err != nil {
			return nil, err
		}
		err = binary.Read(bytes.NewBuffer(buf[14:16]), pr.Endian, &minorVersion)
		if err != nil {
			return nil, err
		}
		err = binary.Read(bytes.NewBuffer(buf[16:24]), pr.Endian, &sectionLength)
		if err != nil {
			return nil, err
		}

		block = &SectionBlock {
			GenericBlock{blockType, blockTotalLength, buf},
			byteOrderMagic,
			majorVersion,
			minorVersion,
			sectionLength,
		}

	} else if blockType == 0x00000001 { // InterfaceBlock

		var linkType   uint16
		var snapLen    uint32

		err = binary.Read(bytes.NewBuffer(buf[8:10]), pr.Endian, &linkType)
		if err != nil {
			return nil, err
		}
		err = binary.Read(bytes.NewBuffer(buf[12:16]), pr.Endian, &snapLen)
		if err != nil {
			return nil, err
		}

		block = &InterfaceBlock {
			GenericBlock{blockType, blockTotalLength, buf},
			linkType,
			snapLen,
		}

	} else if blockType == 0x00000006 { // EnhancedPacketBlock

		var interfaceID          uint32
		var timestampHigh        uint32
		var timestampLow         uint32
		var capturedPacketLength uint32
		var originalPacketLength uint32

		err = binary.Read(bytes.NewBuffer(buf[8:12]), pr.Endian, &interfaceID)
		if err != nil {
			return nil, err
		}
	//  fmt.Printf("interfaceID=%v\n", interfaceID)
		err = binary.Read(bytes.NewBuffer(buf[12:16]), pr.Endian, &timestampHigh)
		if err != nil {
			return nil, err
		}
	//  fmt.Printf("timestampHigh=%v\n", timestampHigh)
		err = binary.Read(bytes.NewBuffer(buf[16:20]), pr.Endian, &timestampLow)
		if err != nil {
			return nil, err
		}
	//  fmt.Printf("timestampLow=%v\n", timestampLow)
		err = binary.Read(bytes.NewBuffer(buf[20:24]), pr.Endian, &capturedPacketLength)
		if err != nil {
			return nil, err
		}
	//  fmt.Printf("capturedPacketLength=%v\n", capturedPacketLength)
		err = binary.Read(bytes.NewBuffer(buf[24:28]), pr.Endian, &originalPacketLength)
		if err != nil {
			return nil, err
		}
	//  fmt.Printf("originalPacketLength=%v\n", originalPacketLength)

		block = &EnhancedPacketBlock {
			GenericBlock{blockType, blockTotalLength, buf},
			interfaceID,
			timestampHigh,
			timestampLow,
			capturedPacketLength,
			originalPacketLength, buf[28:28+capturedPacketLength] }

	} else {
		block = &GenericBlock{ blockType, blockTotalLength, buf }
	}

	return block, nil
}

// PcapngWriter encapsulates all the pcap reading logic
type PcapngWriter struct {
	fh         io.Writer
	Endian     binary.ByteOrder
}

// Writer opens a pcap file for reading.
// It returns a PcapngReader if successful.
func Writer(fh io.Writer) (pw *PcapngWriter) {

	pw = new(PcapngWriter)
	pw.fh = fh
	pw.Endian = binary.LittleEndian
	return pw
}

// Write a block to the pcap file.
func (pw *PcapngWriter) Write(b Block) (err error) {

	buf, err := b.Bytes()
	if err != nil {
		return err
	}
	n, err := pw.fh.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return &PcapError{fmt.Sprintf("wrote %v bytes expected %v\n", n, len(buf))}
	}
	return nil
}
