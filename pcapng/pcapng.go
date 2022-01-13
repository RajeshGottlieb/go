// Package pcap is used to read and write libpcap files.
package pcapng

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Block Types
const (
	INTERFACE_DESCRIPTION_BLOCK = 0x00000001
	NAME_RESOLUTION_BLOCK       = 0x00000004
	INTERFACE_STATISTICS_BLOCK  = 0x00000005
	ENHANCED_PACKET_BLOCK       = 0x00000006
	SECTION_HEADER_BLOCK        = 0x0A0D0D0A
)

// SectionHeaderBlock endianness magic numbers
const (
	MagicNumber     uint32 = 0x1A2B3C4D
	SwapMagicNumber        = 0x4D3C2B1A
)

type Packer interface {
	Pack(endian binary.ByteOrder) ([]byte, error)
}

type Option interface {
	Packer
}

type Block interface {
	Packer
}

type GenericBlock struct {
	Type        uint32
	TotalLength uint32
	Data        []byte // the raw bytes of the block
}

func (b *GenericBlock) Pack(endian binary.ByteOrder) ([]byte, error) {
	return b.Data, nil
}

// Option types
const (
	opt_endofopt = 0
	opt_comment  = 1

	shb_hardware = 2
	shb_os       = 3
	shb_userappl = 4

	if_name        = 2
	if_description = 3
	if_IPv4addr    = 4
	if_IPv6addr    = 5
	if_MACaddr     = 6
	if_EUIaddr     = 7
	if_speed       = 8
	if_tsresol     = 9
	if_tzone       = 10
	if_filter      = 11
	if_os          = 12
	if_fcslen      = 13
	if_tsoffset    = 14
	if_hardware    = 15
	if_txspeed     = 16
	if_rxspeed     = 17

	isb_starttime    = 2
	isb_endtime      = 3
	isb_ifrecv       = 4
	isb_ifdrop       = 5
	isb_filteraccept = 6
	isb_osdrop       = 7
	isb_usrdeliv     = 8
)

func packStringOption(optionType int, optionValue string, endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, endian, uint16(optionType)); err != nil { // Type
		return nil, err
	}
	if err := binary.Write(buf, endian, uint16(len(optionValue))); err != nil { // Length
		return nil, err
	}
	if _, err := buf.Write([]byte(optionValue)); err != nil { // value
		return nil, err
	}

	padding := (4 - (buf.Len() & 3)) & 3
	for i := 0; i < padding; i++ {
		if err := binary.Write(buf, endian, uint8(0)); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

type Opt_Comment struct {
	Value string
}

func (opt *Opt_Comment) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packStringOption(opt_comment, opt.Value, endian)
}

type SectionBlock struct {
	Type           uint32
	TotalLength    uint32
	ByteOrderMagic uint32
	MajorVersion   uint16
	MinorVersion   uint16
	SectionLength  int64
	Options        []Option
}

type Shb_Hardware struct {
	Value string
}

func (opt *Shb_Hardware) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packStringOption(shb_hardware, opt.Value, endian)
}

type Shb_Os struct {
	Value string
}

func (opt *Shb_Os) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packStringOption(shb_os, opt.Value, endian)
}

type Shb_Userappl struct {
	Value string
}

func (opt *Shb_Userappl) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packStringOption(shb_userappl, opt.Value, endian)
}

func packOptions(options []Option, endian binary.ByteOrder) ([]byte, error) {

	buf := new(bytes.Buffer)

	if len(options) > 0 {
		for _, opt := range options {
			bytes, err := opt.Pack(endian)
			if err != nil {
				return nil, err
			}
			buf.Write(bytes)
		}
		if err := binary.Write(buf, endian, uint16(opt_endofopt)); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, endian, uint16(0)); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (b *SectionBlock) Pack(endian binary.ByteOrder) ([]byte, error) {

	options, err := packOptions(b.Options, endian)
	if err != nil {
		return nil, err
	}

	blockTotalLength := uint32(28 + len(options))

	buf := new(bytes.Buffer)

	if err := binary.Write(buf, endian, uint32(SECTION_HEADER_BLOCK)); err != nil { // Block Type
		return nil, err
	}
	if err := binary.Write(buf, endian, blockTotalLength); err != nil { // Block Total Length
		return nil, err
	}
	if err := binary.Write(buf, endian, uint32(0x1A2B3C4D)); err != nil { // Byte-Order Magic
		return nil, err
	}
	if err := binary.Write(buf, endian, uint16(1)); err != nil { // Major Version
		return nil, err
	}
	if err := binary.Write(buf, endian, uint16(0)); err != nil { // Minor Version
		return nil, err
	}
	if err := binary.Write(buf, endian, int64(-1)); err != nil { // Section Length
		return nil, err
	}
	if _, err := buf.Write(options); err != nil { // options
		return nil, err
	}
	if err := binary.Write(buf, endian, blockTotalLength); err != nil { // Block Total Length
		return nil, err
	}

	return buf.Bytes(), nil
}

type InterfaceBlock struct {
	Type        uint32
	TotalLength uint32
	LinkType    uint16
	SnapLen     uint32
	Options     []Option
}

type If_Name struct {
	Value string
}

func (opt *If_Name) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packStringOption(if_name, opt.Value, endian)
}

type If_Tsresol struct {
	Value uint8
}

func (opt *If_Tsresol) Pack(endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, endian, uint16(if_tsresol)); err != nil { // Type
		return nil, err
	}
	if err := binary.Write(buf, endian, uint16(1)); err != nil { // Length
		return nil, err
	}
	if err := binary.Write(buf, endian, uint8(opt.Value)); err != nil { // Value
		return nil, err
	}

	padding := (4 - (buf.Len() & 3)) & 3
	for i := 0; i < padding; i++ {
		if err := binary.Write(buf, endian, uint8(0)); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

type If_Os struct {
	Value string
}

func (opt *If_Os) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packStringOption(if_os, opt.Value, endian)
}

func (b *InterfaceBlock) Pack(endian binary.ByteOrder) ([]byte, error) {

	options, err := packOptions(b.Options, endian)
	if err != nil {
		return nil, err
	}

	blockTotalLength := uint32(20 + len(options))

	buf := new(bytes.Buffer)

	if err := binary.Write(buf, endian, uint32(INTERFACE_DESCRIPTION_BLOCK)); err != nil { // Block Type
		return nil, err
	}
	if err := binary.Write(buf, endian, blockTotalLength); err != nil { // Block Total Length
		return nil, err
	}
	if err := binary.Write(buf, endian, b.LinkType); err != nil { // Link Type
		return nil, err
	}
	if err := binary.Write(buf, endian, uint16(0)); err != nil { // Reserved
		return nil, err
	}
	if err := binary.Write(buf, endian, b.SnapLen); err != nil { // SnapLen
		return nil, err
	}
	if _, err := buf.Write(options); err != nil { // options
		return nil, err
	}
	if err := binary.Write(buf, endian, blockTotalLength); err != nil { // Block Total Length
		return nil, err
	}

	return buf.Bytes(), nil
}

type EnhancedPacketBlock struct {
	Type                 uint32
	TotalLength          uint32
	InterfaceID          uint32
	TimestampHigh        uint32
	TimestampLow         uint32
	CapturedPacketLength uint32
	OriginalPacketLength uint32
	PacketData           []byte // the packet
	Options              []Option
}

func (b *EnhancedPacketBlock) Pack(endian binary.ByteOrder) ([]byte, error) {

	options, err := packOptions(b.Options, endian)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)

	if err := binary.Write(buf, endian, uint32(ENHANCED_PACKET_BLOCK)); err != nil { // Block Type
		return nil, err
	}

	padding := (4 - (len(b.PacketData) & 3)) & 3
	blockTotalLength := uint32(32 + len(b.PacketData) + padding + len(options))

	if err := binary.Write(buf, endian, blockTotalLength); err != nil { // Block Total Length
		return nil, err
	}
	if err := binary.Write(buf, endian, b.InterfaceID); err != nil { // Interface ID
		return nil, err
	}
	if err := binary.Write(buf, endian, b.TimestampHigh); err != nil { // Timestamp (High)
		return nil, err
	}
	if err := binary.Write(buf, endian, b.TimestampLow); err != nil { // Timestamp (Low)
		return nil, err
	}
	if err := binary.Write(buf, endian, uint32(len(b.PacketData))); err != nil { // Captured Packet Length
		return nil, err
	}
	if err := binary.Write(buf, endian, b.OriginalPacketLength); err != nil { // Original Packet Length
		return nil, err
	}

	if _, err := buf.Write(b.PacketData); err != nil { // Packet Data
		return nil, err
	}

	for i := 0; i < padding; i++ {
		if err := binary.Write(buf, endian, uint8(0)); err != nil { // padding
			return nil, err
		}
	}

	if err := binary.Write(buf, endian, blockTotalLength); err != nil { // Block Total Length
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
	fh io.Reader
	//Header     PcapHdr
	Endian binary.ByteOrder
	//NanoSecond bool // true if PcapRecHdr.TsUsec should be interpretted as nano seconds
}

type RawOption struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// Reader opens a pcap file for reading.
// It returns a PcapngReader if successful.
func Reader(fh io.Reader) (pr *PcapngReader) {

	pr = new(PcapngReader)
	pr.fh = fh
	pr.Endian = binary.LittleEndian
	return pr
}

func getRawOptionList(options []byte, endian binary.ByteOrder) (optionList []RawOption, err error) {

	for len(options) > 0 {
		var option RawOption

		if err := binary.Read(bytes.NewBuffer(options[0:2]), endian, &option.Type); err != nil {
			return nil, err
		}
		if err := binary.Read(bytes.NewBuffer(options[2:4]), endian, &option.Length); err != nil {
			return nil, err
		}

		length := int(option.Length)
		if length == 0 {
			//fmt.Printf("optionType=%v optionLength=%v\n", option.Type, option.Length)
			break
		}

		option.Value = options[4 : 4+length]
		padding := (4 - (length & 3)) & 3
		paddedLength := length + padding
		options = options[4+paddedLength:]

		optionList = append(optionList, option)

		//fmt.Printf("optionType=%v optionLength=%v padding=%v paddedLength=%v optionValue=%x\n", option.Type, option.Length, padding, paddedLength, option.Value)
	}
	return optionList, nil
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

	if blockType == SECTION_HEADER_BLOCK { // SectionHeaderBlock
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
	//fmt.Printf("blockTotalLength=%v\n", blockTotalLength)

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

	if blockType == SECTION_HEADER_BLOCK {

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

		optionLen := int(blockTotalLength) - 28
		optionBuf := buf[24 : 24+optionLen]
		rawOptionList, err := getRawOptionList(optionBuf, pr.Endian)
		if err != nil {
			return nil, err
		}

		var options []Option

		for _, opt := range rawOptionList {
			switch opt.Type {
			case opt_comment:
				options = append(options, &Opt_Comment{string(opt.Value)})
			case shb_hardware:
				options = append(options, &Shb_Hardware{string(opt.Value)})
			case shb_os:
				options = append(options, &Shb_Os{string(opt.Value)})
			case shb_userappl:
				options = append(options, &Shb_Userappl{string(opt.Value)})
			}
		}

		block = &SectionBlock{
			blockType,
			blockTotalLength,
			byteOrderMagic,
			majorVersion,
			minorVersion,
			sectionLength,
			options,
		}

	} else if blockType == INTERFACE_DESCRIPTION_BLOCK {

		var linkType uint16
		var snapLen uint32

		if err := binary.Read(bytes.NewBuffer(buf[8:10]), pr.Endian, &linkType); err != nil {
			return nil, err
		}
		if err := binary.Read(bytes.NewBuffer(buf[12:16]), pr.Endian, &snapLen); err != nil {
			return nil, err
		}

		optionLen := int(blockTotalLength) - 20
		optionBuf := buf[16 : 16+optionLen]
		rawOptionList, err := getRawOptionList(optionBuf, pr.Endian)
		if err != nil {
			return nil, err
		}

		var options []Option

		for _, opt := range rawOptionList {
			fmt.Printf(" opt.Type=%v opt.Length=%v opt.Value=%x\n", opt.Type, opt.Length, opt.Value)
			switch opt.Type {
			case opt_comment:
				options = append(options, &Opt_Comment{string(opt.Value)})
			case if_name:
				options = append(options, &If_Name{string(opt.Value)})
			case if_tsresol:
				options = append(options, &If_Tsresol{uint8(opt.Value[0])})
			case if_os:
				options = append(options, &If_Os{string(opt.Value)})
			}
		}

		block = &InterfaceBlock{
			blockType,
			blockTotalLength,
			linkType,
			snapLen,
			options,
		}

	} else if blockType == ENHANCED_PACKET_BLOCK {

		var interfaceID uint32
		var timestampHigh uint32
		var timestampLow uint32
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
		//fmt.Printf("capturedPacketLength=%v\n", capturedPacketLength)
		if err := binary.Read(bytes.NewBuffer(buf[24:28]), pr.Endian, &originalPacketLength); err != nil {
			return nil, err
		}
		//  fmt.Printf("originalPacketLength=%v\n", originalPacketLength)
		packetPadding := (4 - (int(capturedPacketLength) & 3)) & 3
		paddedPacketLen := int(capturedPacketLength) + packetPadding
		//fmt.Printf("paddedPacketLen=%v\n", paddedPacketLen)

		optionLen := int(blockTotalLength) - (32 + paddedPacketLen)
		//fmt.Printf("optionLen=%v\n", optionLen)
		optionBuf := buf[28+paddedPacketLen : 28+paddedPacketLen+optionLen]
		rawOptionList, err := getRawOptionList(optionBuf, pr.Endian)
		if err != nil {
			return nil, err
		}

		var options []Option

		// TODO not the right options
		for _, opt := range rawOptionList {
			fmt.Printf(" opt.Type=%v opt.Length=%v opt.Value=%x\n", opt.Type, opt.Length, opt.Value)
			switch opt.Type {
			case opt_comment:
				options = append(options, &Opt_Comment{string(opt.Value)})
			case if_name:
				options = append(options, &If_Name{string(opt.Value)})
			case if_tsresol:
				options = append(options, &If_Tsresol{uint8(opt.Value[0])})
			case if_os:
				options = append(options, &If_Os{string(opt.Value)})
			}
		}

		block = &EnhancedPacketBlock{
			blockType,
			blockTotalLength,
			interfaceID,
			timestampHigh,
			timestampLow,
			capturedPacketLength,
			originalPacketLength,
			buf[28 : 28+capturedPacketLength],
			options}

	} else {
		block = &GenericBlock{blockType, blockTotalLength, buf}
	}

	return block, nil
}

// PcapngWriter encapsulates all the pcapng writing logic
type PcapngWriter struct {
	fh     io.Writer
	Endian binary.ByteOrder
}

// Writer opens a pcap file for writing.
// It returns a PcapngWriter if successful.
func Writer(fh io.Writer) (pw *PcapngWriter) {

	pw = new(PcapngWriter)
	pw.fh = fh
	pw.Endian = binary.LittleEndian
	return pw
}

// Write a block to io.Writer
func Write(fh io.Writer, b Block, endian binary.ByteOrder) (err error) {

	buf, err := b.Pack(endian)
	if err != nil {
		return err
	}

	if n, err := fh.Write(buf); err != nil {
		return err
	} else if n != len(buf) {
		return &PcapError{fmt.Sprintf("wrote %v bytes expected %v\n", n, len(buf))}
	}
	return nil
}

// Write a block to the pcap file.
func (pw *PcapngWriter) Write(b Block) (err error) {
	return Write(pw.fh, b, pw.Endian)
}
