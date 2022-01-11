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
	Type		uint32
	TotalLength	uint32
	ByteOrderMagic  uint32
	MajorVersion    uint16
	MinorVersion    uint16
	SectionLength   int64
}

func (b *SectionBlock) Bytes() ([]byte, error) {

	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.LittleEndian, uint32(0x0A0D0D0A)); err != nil { // Block Type
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(28)); err != nil { // Block Total Length
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(0x1A2B3C4D)); err != nil { // Byte-Order Magic
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint16(1)); err != nil { // Major Version
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint16(0)); err != nil { // Minor Version
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, int64(-1)); err != nil { // Section Length
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(28)); err != nil { // Block Total Length
		return nil, err
	}

	return buf.Bytes(), nil
}

// Block Type = 0x00000001
type InterfaceBlock struct {
	Type		uint32
	TotalLength	uint32
	LinkType    uint16
	SnapLen    uint32
}

func (b *InterfaceBlock) Bytes() ([]byte, error) {

	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.LittleEndian, uint32(0x00000001)); err != nil { // Block Type
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(20)); err != nil { // Block Total Length
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, b.LinkType); err != nil { // Link Type
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint16(0)); err != nil { // Reserved
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, b.SnapLen); err != nil { // SnapLen
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(20)); err != nil { // Block Total Length
		return nil, err
	}

	return buf.Bytes(), nil
}

type EnhancedPacketBlock struct {
	Type		uint32
	TotalLength	uint32
	InterfaceID          uint32
	TimestampHigh        uint32
	TimestampLow         uint32
	CapturedPacketLength uint32
	OriginalPacketLength uint32
    PacketData		     []byte	// the packet
}

func (b *EnhancedPacketBlock) Bytes() ([]byte, error) {

	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.LittleEndian, uint32(0x00000006)); err != nil { // Block Type
		return nil, err
	}

	padding := (4 - (len(b.PacketData) & 3)) & 3
	blockTotalLength := uint32(32 + len(b.PacketData) + padding)

	if err := binary.Write(buf, binary.LittleEndian, blockTotalLength); err != nil { // Block Total Length
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, b.InterfaceID); err != nil { // Interface ID
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, b.TimestampHigh); err != nil { // Timestamp (High)
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, b.TimestampLow); err != nil { // Timestamp (Low)
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(b.PacketData))); err != nil { // Captured Packet Length
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, b.OriginalPacketLength); err != nil { // Original Packet Length
		return nil, err
	}

	if _, err := buf.Write(b.PacketData); err != nil { // Packet Data
		return nil, err
	}

	for i := 0; i < padding; i++ {
		if err := binary.Write(buf, binary.LittleEndian, uint8(0)); err != nil { // padding
			return nil, err
		}
	}

	if err := binary.Write(buf, binary.LittleEndian, blockTotalLength); err != nil { // Block Total Length
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

	// read block type and block length
	if count, err := pr.fh.Read(buf); err != nil {
		return nil, err
	} else if count != len(buf) {
		return nil, &PcapError{fmt.Sprintf("read %v packet header bytes expected %v\n", count, len(buf))}
	}

	var blockType uint32

	if err := binary.Read(bytes.NewReader(buf[0:4]), pr.Endian, &blockType); err != nil {
		return nil, err
	}
//  fmt.Printf("blockType=0x%08x\n", blockType)

	var byteOrderMagic uint32

	if blockType == 0x0A0D0D0A { // SectionHeaderBlock
		// The endianness is indicated by the Section Header Block
		//var byteOrderMagic uint32
		if err := binary.Read(bytes.NewReader(buf[8:12]), pr.Endian, &byteOrderMagic); err != nil {
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
	if err := binary.Read(bytes.NewReader(buf[4:8]), pr.Endian, &blockTotalLength); err != nil {
		return nil, err
	}
//  fmt.Printf("blockTotalLength=%v\n", blockTotalLength)

	// read the rest of the block
	if len(buf) < int(blockTotalLength) {
		grow := make([]byte, blockTotalLength)
		copy(grow, buf)
		buf = grow

		// read the rest of the block
		if count, err := pr.fh.Read(buf[12:]); err != nil {
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

		if err := binary.Read(bytes.NewBuffer(buf[12:14]), pr.Endian, &majorVersion); err != nil {
			return nil, err
		}
		if err := binary.Read(bytes.NewBuffer(buf[14:16]), pr.Endian, &minorVersion); err != nil {
			return nil, err
		}
		if err := binary.Read(bytes.NewBuffer(buf[16:24]), pr.Endian, &sectionLength); err != nil {
			return nil, err
		}

		block = &SectionBlock {
			blockType,
			blockTotalLength,
			byteOrderMagic,
			majorVersion,
			minorVersion,
			sectionLength,
		}

	} else if blockType == 0x00000001 { // InterfaceBlock

		var linkType   uint16
		var snapLen    uint32

		if err := binary.Read(bytes.NewBuffer(buf[8:10]), pr.Endian, &linkType); err != nil {
			return nil, err
		}
		if err := binary.Read(bytes.NewBuffer(buf[12:16]), pr.Endian, &snapLen); err != nil {
			return nil, err
		}

		block = &InterfaceBlock {
			blockType,
			blockTotalLength,
			linkType,
			snapLen,
		}

	} else if blockType == 0x00000006 { // EnhancedPacketBlock

		var interfaceID          uint32
		var timestampHigh        uint32
		var timestampLow         uint32
		var capturedPacketLength uint32
		var originalPacketLength uint32

		if err := binary.Read(bytes.NewBuffer(buf[8:12]), pr.Endian, &interfaceID); err != nil {
			return nil, err
		}
	//  fmt.Printf("interfaceID=%v\n", interfaceID)
		if err := binary.Read(bytes.NewBuffer(buf[12:16]), pr.Endian, &timestampHigh); err != nil {
			return nil, err
		}
	//  fmt.Printf("timestampHigh=%v\n", timestampHigh)
		if err := binary.Read(bytes.NewBuffer(buf[16:20]), pr.Endian, &timestampLow); err != nil {
			return nil, err
		}
	//  fmt.Printf("timestampLow=%v\n", timestampLow)
		if err := binary.Read(bytes.NewBuffer(buf[20:24]), pr.Endian, &capturedPacketLength); err != nil {
			return nil, err
		}
	//  fmt.Printf("capturedPacketLength=%v\n", capturedPacketLength)
		if err := binary.Read(bytes.NewBuffer(buf[24:28]), pr.Endian, &originalPacketLength); err != nil {
			return nil, err
		}
	//  fmt.Printf("originalPacketLength=%v\n", originalPacketLength)

		block = &EnhancedPacketBlock {
			blockType,
			blockTotalLength,
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

// PcapngWriter encapsulates all the pcapng writing logic
type PcapngWriter struct {
	fh         io.Writer
	Endian     binary.ByteOrder
}

// Writer opens a pcap file for writing.
// It returns a PcapngWriter if successful.
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
