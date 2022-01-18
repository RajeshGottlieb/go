package main

import (
	"fmt"
	"github.com/RajeshGottlieb/go/pcapng"
	"io"
	"os"
)

func main() {

	if len(os.Args) != 3 {
		fmt.Printf("usage: %v <input-pcapng> <output-text>\n", os.Args[0])
		return
	}

	rfh, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer rfh.Close()

	pr := pcapng.Reader(rfh)

	wfh, err := os.Create(os.Args[2])
	if err != nil {
		panic(err)
	}
	defer wfh.Close()

	pw := pcapng.Writer(wfh)

	for count := 0; true; count++ {

		block, err := pr.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}

		if b, ok := block.(*pcapng.SectionBlock); ok {

			fmt.Printf("# SectionBlock %v: Type=0x%08x TotalLength=%v\n", count+1, b.Type, b.TotalLength)

			for _, opt := range b.Options {
				switch option := opt.(type) {
				case *pcapng.Opt_Comment:
					fmt.Printf("#  opt_comment=%v\n", option.Value)
				case *pcapng.Shb_Hardware:
					fmt.Printf("#  shb_hardware=%v\n", option.Value)
				case *pcapng.Shb_Os:
					fmt.Printf("#  shb_os=%v\n", option.Value)
				case *pcapng.Shb_Userappl:
					fmt.Printf("#  shb_userappl=%v\n", option.Value)
				default:
				}
			}

			if err = pw.Write(b); err != nil {
				panic(err)
			}

		} else if b, ok := block.(*pcapng.InterfaceBlock); ok {

			fmt.Printf("# InterfaceBlock %v: Type=0x%08x TotalLength=%v LinkType=%v SnapLen=%v\n", count+1, b.Type, b.TotalLength, b.LinkType, b.SnapLen)

			for _, opt := range b.Options {
				switch option := opt.(type) {
				case *pcapng.Opt_Comment:
					fmt.Printf("#  opt_comment=%v\n", option.Value)
				case *pcapng.If_Name:
					fmt.Printf("#  if_name=%v\n", option.Value)
				case *pcapng.If_Tsresol:
					fmt.Printf("#  if_tsresol=%v\n", option.Value)
				case *pcapng.If_Os:
					fmt.Printf("#  if_os=%v\n", option.Value)
				default:
				}
			}

			if err = pw.Write(b); err != nil {
				panic(err)
			}

		} else if b, ok := block.(*pcapng.InterfaceStatisticsBlock); ok {

			fmt.Printf("# InterfaceStatisticsBlock %v: Type=0x%08x TotalLength=%v\n", count+1, b.Type, b.TotalLength)

			for _, opt := range b.Options {
				switch option := opt.(type) {
				case *pcapng.Opt_Comment:
					fmt.Printf("#  opt_comment=%v\n", option.Value)
				case *pcapng.Isb_Starttime:
					fmt.Printf("#  isb_starttime=%v,%v\n", option.TimestampHigh, option.TimestampLow)
				case *pcapng.Isb_Endtime:
					fmt.Printf("#  isb_endtime=%v,%v\n", option.TimestampHigh, option.TimestampLow)
				case *pcapng.Isb_Ifrecv:
					fmt.Printf("#  isb_ifrecv=%v\n", option.Value)
				case *pcapng.Isb_Ifdrop:
					fmt.Printf("#  isb_ifdrop=%v\n", option.Value)
				case *pcapng.Isb_Filteraccept:
					fmt.Printf("#  isb_filteraccept=%v\n", option.Value)
				case *pcapng.Isb_Osdrop:
					fmt.Printf("#  isb_osdrop=%v\n", option.Value)
				case *pcapng.Isb_Usrdeliv:
					fmt.Printf("#  isb_usrdeliv=%v\n", option.Value)
				}
			}

			if err = pw.Write(b); err != nil {
				panic(err)
			}

		} else if b, ok := block.(*pcapng.EnhancedPacketBlock); ok {

			fmt.Printf("# EnhancedPacketBlock %v: Type=0x%08x TotalLength=%v InterfaceID=%v\n", count+1, b.Type, b.TotalLength, b.InterfaceID)

			for _, opt := range b.Options {
				switch option := opt.(type) {
				case *pcapng.Opt_Comment:
					fmt.Printf("#  opt_comment=%v\n", option.Value)
				case *pcapng.Epb_Flags:
					fmt.Printf("#  epb_flags=%v\n", option.Value)
				case *pcapng.Epb_Hash:
					fmt.Printf("#  epb_hash=%v,%v\n", option.Value)
				case *pcapng.Epb_Dropcount:
					fmt.Printf("#  epb_dropcount=%v\n", option.Value)
				case *pcapng.Epb_Packetid:
					fmt.Printf("#  epb_packetid=%v\n", option.Value)
				case *pcapng.Epb_Queue:
					fmt.Printf("#  epb_queue=%v\n", option.Value)
				}
			}

			if err = pw.Write(b); err != nil {
				panic(err)
			}

		} else if b, ok := block.(*pcapng.NameResolutionBlock); ok {

			fmt.Printf("# NameResolutionBlock %v: Type=0x%08x TotalLength=%v\n", count+1, b.Type, b.TotalLength)
			if err = pw.Write(b); err != nil {
				panic(err)
			}

			for _, rec := range b.Records {
				switch record := rec.(type) {
				case *pcapng.Nrb_Record_ipv4:
					fmt.Printf("#  nrb_record_ipv4=%x\n", record.Value)
				case *pcapng.Nrb_Record_ipv6:
					fmt.Printf("#  nrb_record_ipv6=%x\n", record.Value)
				}
			}

			for _, opt := range b.Options {
				switch option := opt.(type) {
				case *pcapng.Opt_Comment:
					fmt.Printf("#  opt_comment=%v\n", option.Value)
				case *pcapng.Ns_Dnsname:
					fmt.Printf("#  ns_dnsname=%v\n", option.Value)
				case *pcapng.Ns_DnsIP4addr:
					fmt.Printf("#  ns_dnsIP4addr=%x\n", option.Value)
				case *pcapng.Ns_DnsIP6addr:
					fmt.Printf("#  ns_dnsIP6addr=%x\n", option.Value)
				}
			}

		} else if b, ok := block.(*pcapng.GenericBlock); ok {

			fmt.Printf("# GenericBlock %v: Type=0x%08x TotalLength=%v len(Data)=%v\n", count+1, b.Type, b.TotalLength, len(b.Data))
			if err = pw.Write(b); err != nil {
				panic(err)
			}

		}
	}
}
