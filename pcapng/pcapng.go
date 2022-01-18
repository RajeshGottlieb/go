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

// Section Header Block endianness magic numbers
const (
	MagicNumber     = 0x1A2B3C4D
	SwapMagicNumber = 0x4D3C2B1A
)

type Packer interface {
	Pack(endian binary.ByteOrder) ([]byte, error)
	//Unpack([]byte buf, endian binary.ByteOrder) (error)
}

type Option interface {
	Packer
}

type NbrRecord interface {
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

	// Section Header Block
	shb_hardware = 2
	shb_os       = 3
	shb_userappl = 4

	// Interface Description Block
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

	// Interface Statistics Block
	isb_starttime    = 2
	isb_endtime      = 3
	isb_ifrecv       = 4
	isb_ifdrop       = 5
	isb_filteraccept = 6
	isb_osdrop       = 7
	isb_usrdeliv     = 8

	// Enhanced Packet Block
	epb_flags     = 2
	epb_hash      = 3
	epb_dropcount = 4
	epb_packetid  = 5
	epb_queue     = 6
	epb_verdict   = 7

	// Name Resolution Block
	ns_dnsname    = 2
	ns_dnsIP4addr = 3
	ns_dnsIP6addr = 4
)

// Name Resolution Record types
const (
	nrb_record_end  = 0
	nrb_record_ipv4 = 1
	nrb_record_ipv6 = 2
)

func packTlv(tlvType int, tlvValue []byte, endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, endian, uint16(tlvType)); err != nil { // Type
		return nil, err
	}
	if err := binary.Write(buf, endian, uint16(len(tlvValue))); err != nil { // Length
		return nil, err
	}
	if _, err := buf.Write(tlvValue); err != nil { // value
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
	return packTlv(opt_comment, []byte(opt.Value), endian)
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
	return packTlv(shb_hardware, []byte(opt.Value), endian)
}

type Shb_Os struct {
	Value string
}

func (opt *Shb_Os) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packTlv(shb_os, []byte(opt.Value), endian)
}

type Shb_Userappl struct {
	Value string
}

func (opt *Shb_Userappl) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packTlv(shb_userappl, []byte(opt.Value), endian)
}

func packOptions(options []Option, endian binary.ByteOrder) ([]byte, error) {

	buf := new(bytes.Buffer)

	// All the block bodies MAY embed optional fields.
	if len(options) > 0 {
		for _, opt := range options {
			bytes, err := opt.Pack(endian)
			if err != nil {
				return nil, err
			}
			buf.Write(bytes)
		}
		// Code that writes pcapng files MUST put an opt_endofopt option at the end of an option list.
		if err := binary.Write(buf, endian, uint16(opt_endofopt)); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, endian, uint16(0)); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func packRecords(records []NbrRecord, endian binary.ByteOrder) ([]byte, error) {

	buf := new(bytes.Buffer)

	for _, rec := range records {
		bytes, err := rec.Pack(endian)
		if err != nil {
			return nil, err
		}
		buf.Write(bytes)
	}
	// An nrb_record_end MUST be added after the last Record, and
	// MUST exist even if there are no other Records in the NRB.
	if err := binary.Write(buf, endian, uint16(nrb_record_end)); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, endian, uint16(0)); err != nil {
		return nil, err
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
	return packTlv(if_name, []byte(opt.Value), endian)
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
	return packTlv(if_os, []byte(opt.Value), endian)
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

type InterfaceStatisticsBlock struct {
	Type          uint32
	TotalLength   uint32
	InterfaceID   uint32
	TimestampHigh uint32
	TimestampLow  uint32
	Options       []Option
}

func (b *InterfaceStatisticsBlock) Pack(endian binary.ByteOrder) ([]byte, error) {

	options, err := packOptions(b.Options, endian)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)

	if err := binary.Write(buf, endian, uint32(INTERFACE_STATISTICS_BLOCK)); err != nil { // Block Type
		return nil, err
	}

	blockTotalLength := uint32(24 + len(options))

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
	if _, err := buf.Write(options); err != nil { // options
		return nil, err
	}
	if err := binary.Write(buf, endian, blockTotalLength); err != nil { // Block Total Length
		return nil, err
	}

	return buf.Bytes(), nil
}

type Isb_Starttime struct {
	TimestampHigh uint32
	TimestampLow  uint32
}

func (opt *Isb_Starttime) Pack(endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, endian, opt); err != nil {
		return nil, err
	}
	return packTlv(isb_starttime, buf.Bytes(), endian)
}

type Isb_Endtime struct {
	TimestampHigh uint32
	TimestampLow  uint32
}

func (opt *Isb_Endtime) Pack(endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, endian, opt); err != nil {
		return nil, err
	}
	return packTlv(isb_endtime, buf.Bytes(), endian)
}

type Isb_Ifrecv struct {
	Value uint64
}

func (opt *Isb_Ifrecv) Pack(endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, endian, opt); err != nil {
		return nil, err
	}
	return packTlv(isb_ifrecv, buf.Bytes(), endian)
}

type Isb_Ifdrop struct {
	Value uint64
}

func (opt *Isb_Ifdrop) Pack(endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, endian, opt); err != nil {
		return nil, err
	}
	return packTlv(isb_ifdrop, buf.Bytes(), endian)
}

type Isb_Filteraccept struct {
	Value uint64
}

func (opt *Isb_Filteraccept) Pack(endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, endian, opt); err != nil {
		return nil, err
	}
	return packTlv(isb_filteraccept, buf.Bytes(), endian)
}

type Isb_Osdrop struct {
	Value uint64
}

func (opt *Isb_Osdrop) Pack(endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, endian, opt); err != nil {
		return nil, err
	}
	return packTlv(isb_osdrop, buf.Bytes(), endian)
}

type Isb_Usrdeliv struct {
	Value uint64
}

func (opt *Isb_Usrdeliv) Pack(endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, endian, opt); err != nil {
		return nil, err
	}
	return packTlv(isb_usrdeliv, buf.Bytes(), endian)
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
	if _, err := buf.Write(options); err != nil { // options
		return nil, err
	}

	if err := binary.Write(buf, endian, blockTotalLength); err != nil { // Block Total Length
		return nil, err
	}

	return buf.Bytes(), nil
}

type Epb_Flags struct {
	Value uint32
}

func (opt *Epb_Flags) Pack(endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, endian, opt); err != nil {
		return nil, err
	}
	return packTlv(epb_flags, buf.Bytes(), endian)
}

type Epb_Hash struct {
	Value []uint8
}

func (opt *Epb_Hash) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packTlv(epb_hash, opt.Value, endian)
}

type Epb_Dropcount struct {
	Value uint64
}

func (opt *Epb_Dropcount) Pack(endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, endian, opt); err != nil {
		return nil, err
	}
	return packTlv(epb_hash, buf.Bytes(), endian)
}

type Epb_Packetid struct {
	Value uint64
}

func (opt *Epb_Packetid) Pack(endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, endian, opt); err != nil {
		return nil, err
	}
	return packTlv(epb_hash, buf.Bytes(), endian)
}

type Epb_Queue struct {
	Value uint32
}

func (opt *Epb_Queue) Pack(endian binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, endian, opt); err != nil {
		return nil, err
	}
	return packTlv(epb_queue, buf.Bytes(), endian)
}

/*
type Epb_Verdict struct {
	// TODO
}
*/

type NameResolutionBlock struct {
	Type                 uint32
	TotalLength          uint32
	Records              []NbrRecord
	Options              []Option
}

func (b *NameResolutionBlock) Pack(endian binary.ByteOrder) ([]byte, error) {

	records, err := packRecords(b.Records, endian)
	if err != nil {
		return nil, err
	}

	options, err := packOptions(b.Options, endian)
	if err != nil {
		return nil, err
	}

	blockTotalLength := uint32(12 + len(records) + len(options))

	buf := new(bytes.Buffer)

	if err := binary.Write(buf, endian, uint32(NAME_RESOLUTION_BLOCK)); err != nil { // Block Type
		return nil, err
	}
	if err := binary.Write(buf, endian, blockTotalLength); err != nil { // Block Total Length
		return nil, err
	}

	if _, err := buf.Write(records); err != nil { // records
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

// 
type Nrb_Record_ipv4 struct {
	Value []byte
}

type Nrb_Record_ipv6 struct {
	Value []byte
}

func (rec *Nrb_Record_ipv4) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packTlv(nrb_record_ipv4, rec.Value, endian)
}

func (rec *Nrb_Record_ipv6) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packTlv(nrb_record_ipv6, rec.Value, endian)
}

type Ns_Dnsname struct {
	Value string
}

func (opt *Ns_Dnsname) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packTlv(ns_dnsname, []byte(opt.Value), endian)
}

type Ns_DnsIP4addr struct {
	Value [4]byte
}

func (opt *Ns_DnsIP4addr) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packTlv(ns_dnsIP4addr, opt.Value[:], endian)
}

type Ns_DnsIP6addr struct {
	Value [16]byte
}

func (opt *Ns_DnsIP6addr) Pack(endian binary.ByteOrder) ([]byte, error) {
	return packTlv(ns_dnsIP6addr, opt.Value[:], endian)
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

type TLV struct {
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

func getTlvList(buf []byte, endian binary.ByteOrder) (remainingBuf []byte, tlvList []TLV, err error) {

	for len(buf) > 0 {
		var tlv TLV

		if err := binary.Read(bytes.NewBuffer(buf[0:2]), endian, &tlv.Type); err != nil {
			return nil, nil, err
		}
		if err := binary.Read(bytes.NewBuffer(buf[2:4]), endian, &tlv.Length); err != nil {
			return nil, nil, err
		}
		buf = buf[4:]

		// is this the last TLV
		if tlv.Type == 0 && tlv.Length == 0 {
			break
		}

		length := int(tlv.Length)

		tlv.Value = buf[:length]
		padding := (4 - (length & 3)) & 3
		paddedLength := length + padding

		buf = buf[paddedLength:]

		tlvList = append(tlvList, tlv)

		//fmt.Printf("optionType=%v optionLength=%v padding=%v paddedLength=%v optionValue=%x\n", tlv.Type, tlv.Length, padding, paddedLength, tlv.Value)
	}
	return buf, tlvList, nil
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

	if blockType == SECTION_HEADER_BLOCK {
		// The endianness is indicated by the Section Header Block

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
		_, tlvList, err := getTlvList(optionBuf, pr.Endian)
		if err != nil {
			return nil, err
		}

		var options []Option

		for _, tlv := range tlvList {
			switch tlv.Type {
			case opt_comment:
				options = append(options, &Opt_Comment{string(tlv.Value)})
			case shb_hardware:
				options = append(options, &Shb_Hardware{string(tlv.Value)})
			case shb_os:
				options = append(options, &Shb_Os{string(tlv.Value)})
			case shb_userappl:
				options = append(options, &Shb_Userappl{string(tlv.Value)})
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
		_, tlvList, err := getTlvList(optionBuf, pr.Endian)
		if err != nil {
			return nil, err
		}

		var options []Option

		for _, tlv := range tlvList {
			//fmt.Printf(" tlv.Type=%v tlv.Length=%v tlv.Value=%x\n", tlv.Type, tlv.Length, tlv.Value)
			switch tlv.Type {
			case opt_comment:
				options = append(options, &Opt_Comment{string(tlv.Value)})
			case if_name:
				options = append(options, &If_Name{string(tlv.Value)})
			case if_tsresol:
				options = append(options, &If_Tsresol{uint8(tlv.Value[0])})
			case if_os:
				options = append(options, &If_Os{string(tlv.Value)})
			}
		}

		block = &InterfaceBlock{
			blockType,
			blockTotalLength,
			linkType,
			snapLen,
			options,
		}

	} else if blockType == INTERFACE_STATISTICS_BLOCK {

		var interfaceID uint32
		var timestampHigh uint32
		var timestampLow uint32

		if err := binary.Read(bytes.NewBuffer(buf[8:12]), pr.Endian, &interfaceID); err != nil {
			return nil, err
		}
		if err := binary.Read(bytes.NewBuffer(buf[12:16]), pr.Endian, &timestampHigh); err != nil {
			return nil, err
		}
		if err := binary.Read(bytes.NewBuffer(buf[16:20]), pr.Endian, &timestampLow); err != nil {
			return nil, err
		}
		//fmt.Printf("interfaceID=%v\n", interfaceID)
		//fmt.Printf("timestampHigh=%v\n", timestampHigh)

		optionLen := int(blockTotalLength) - 24
		optionBuf := buf[20 : 20+optionLen]
		_, tlvList, err := getTlvList(optionBuf, pr.Endian)
		if err != nil {
			return nil, err
		}

		var options []Option

		for _, tlv := range tlvList {
			switch tlv.Type {
			case opt_comment:
				options = append(options, &Opt_Comment{string(tlv.Value)})
			case isb_starttime:
				var option Isb_Starttime
				if err := binary.Read(bytes.NewBuffer(tlv.Value), pr.Endian, &option); err != nil {
					return nil, err
				}
				options = append(options, &option)
			case isb_endtime:
				var option Isb_Endtime
				if err := binary.Read(bytes.NewBuffer(tlv.Value), pr.Endian, &option); err != nil {
					return nil, err
				}
				options = append(options, &option)
			case isb_ifrecv:
				var option Isb_Ifrecv
				if err := binary.Read(bytes.NewBuffer(tlv.Value), pr.Endian, &option); err != nil {
					return nil, err
				}
				options = append(options, &option)
			case isb_ifdrop:
				var option Isb_Ifdrop
				if err := binary.Read(bytes.NewBuffer(tlv.Value), pr.Endian, &option); err != nil {
					return nil, err
				}
				options = append(options, &option)
			case isb_filteraccept:
				var option Isb_Filteraccept
				if err := binary.Read(bytes.NewBuffer(tlv.Value), pr.Endian, &option); err != nil {
					return nil, err
				}
				options = append(options, &option)
			case isb_osdrop:
				var option Isb_Osdrop
				if err := binary.Read(bytes.NewBuffer(tlv.Value), pr.Endian, &option); err != nil {
					return nil, err
				}
				options = append(options, &option)
			case isb_usrdeliv:
				var option Isb_Usrdeliv
				if err := binary.Read(bytes.NewBuffer(tlv.Value), pr.Endian, &option); err != nil {
					return nil, err
				}
				options = append(options, &option)
			}
		}

		block = &InterfaceStatisticsBlock{
			blockType,
			blockTotalLength,
			interfaceID,
			timestampHigh,
			timestampLow,
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
		if err := binary.Read(bytes.NewBuffer(buf[12:16]), pr.Endian, &timestampHigh); err != nil {
			return nil, err
		}
		if err := binary.Read(bytes.NewBuffer(buf[16:20]), pr.Endian, &timestampLow); err != nil {
			return nil, err
		}
		if err := binary.Read(bytes.NewBuffer(buf[20:24]), pr.Endian, &capturedPacketLength); err != nil {
			return nil, err
		}
		if err := binary.Read(bytes.NewBuffer(buf[24:28]), pr.Endian, &originalPacketLength); err != nil {
			return nil, err
		}
		//fmt.Printf("interfaceID=%v\n", interfaceID)
		//fmt.Printf("timestampHigh=%v\n", timestampHigh)
		//fmt.Printf("timestampLow=%v\n", timestampLow)
		//fmt.Printf("capturedPacketLength=%v\n", capturedPacketLength)

		packetData := buf[28 : 28+capturedPacketLength]
		//fmt.Printf("originalPacketLength=%v\n", originalPacketLength)
		packetPadding := (4 - (len(packetData) & 3)) & 3
		paddedPacketLen := len(packetData) + packetPadding
		//fmt.Printf("paddedPacketLen=%v\n", paddedPacketLen)

		optionLen := int(blockTotalLength) - (32 + paddedPacketLen)
		//fmt.Printf("optionLen=%v\n", optionLen)
		optionBuf := buf[28+paddedPacketLen : 28+paddedPacketLen+optionLen]
		_, tlvList, err := getTlvList(optionBuf, pr.Endian)
		if err != nil {
			return nil, err
		}

		var options []Option

		for _, tlv := range tlvList {
			//fmt.Printf(" tlv.Type=%v tlv.Length=%v tlv.Value=%x\n", tlv.Type, tlv.Length, tlv.Value)
			switch tlv.Type {
			case opt_comment:
				options = append(options, &Opt_Comment{string(tlv.Value)})
			case epb_flags:
				var option Epb_Flags
				if err := binary.Read(bytes.NewBuffer(tlv.Value), pr.Endian, &option); err != nil {
					return nil, err
				}
				options = append(options, &option)
			case epb_hash:
				var option Epb_Hash
				if err := binary.Read(bytes.NewBuffer(tlv.Value), pr.Endian, &option); err != nil {
					return nil, err
				}
				options = append(options, &option)
			case epb_dropcount:
				var option Epb_Dropcount
				if err := binary.Read(bytes.NewBuffer(tlv.Value), pr.Endian, &option); err != nil {
					return nil, err
				}
				options = append(options, &option)
			case epb_packetid:
				var option Epb_Packetid
				if err := binary.Read(bytes.NewBuffer(tlv.Value), pr.Endian, &option); err != nil {
					return nil, err
				}
				options = append(options, &option)
			case epb_queue:
				var option Epb_Queue
				if err := binary.Read(bytes.NewBuffer(tlv.Value), pr.Endian, &option); err != nil {
					return nil, err
				}
				options = append(options, &option)
				/*
					case epb_verdict:
				*/
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
			packetData,
			options}

	} else if blockType == NAME_RESOLUTION_BLOCK {

		// get records
		bodyLen := int(blockTotalLength) - 12
		body := buf[8 : 8+bodyLen]
		body, tlvList, err := getTlvList(body, pr.Endian)
		if err != nil {
			return nil, err
		}

		var records []NbrRecord

		for _, tlv := range tlvList {
			//fmt.Printf("tlv.Type=%v tlv.Length=%v tlv.Value=%x\n", tlv.Type, tlv.Length, tlv.Value)
			switch tlv.Type {
			case nrb_record_ipv4:
				records = append(records, &Nrb_Record_ipv4{tlv.Value})
			case nrb_record_ipv6:
				records = append(records, &Nrb_Record_ipv6{tlv.Value})
			}
		}

		_, tlvList, err = getTlvList(body, pr.Endian)
		if err != nil {
			return nil, err
		}

		var options []Option

		for _, tlv := range tlvList {
			//fmt.Printf("tlv.Type=%v tlv.Length=%v tlv.Value=%x\n", tlv.Type, tlv.Length, tlv.Value)
			switch tlv.Type {
			case opt_comment:
				options = append(options, &Opt_Comment{string(tlv.Value)})
			case ns_dnsname:
				options = append(options, &Ns_Dnsname{string(tlv.Value)})
			case ns_dnsIP4addr:
				var option Ns_DnsIP4addr
				copy(option.Value[:], tlv.Value)
				options = append(options, &option)
			case ns_dnsIP6addr:
				var option Ns_DnsIP6addr
				copy(option.Value[:], tlv.Value)
				options = append(options, &option)
			}
		}

		block = &NameResolutionBlock{
			blockType,
			blockTotalLength,
			records,
			options}

	} else {
		fmt.Printf("#### unhandled block type %v ####\n", blockType)
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
