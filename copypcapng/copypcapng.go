package main

import (
	//"encoding/hex"
	"github.com/RajeshGottlieb/go/pcapng"
	//"bytes"
	//"encoding/binary"
	"fmt"
	"io"
	"os"
	//"time"
)

const (
	OFF      = "\033[0m"
	RED      = "\033[31m"
	GREEN    = "\033[32m"
	YELLOW   = "\033[33m"
	BLUE     = "\033[34m"
	MAGENTA  = "\033[35m"
	CYAN     = "\033[36m"
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

	pr := pcapng2.Reader(rfh)

	wfh, err := os.Create(os.Args[2])
	if err != nil {
		panic(err)
	}
	defer wfh.Close()

	pw := pcapng2.Writer(wfh)

	for count := 0; true; count++ {

		block, err := pr.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}

		if sb, ok := block.(*pcapng2.SectionBlock); ok {

			fmt.Printf("# SectionBlock %v: Type=0x%08x TotalLength=%v len(Data)=%v\n", count+1, sb.Type, sb.TotalLength, len(sb.Data))
			if err = pw.Write(sb); err != nil {
				panic(err)
			}

		} else if ib, ok := block.(*pcapng2.InterfaceBlock); ok {

			fmt.Printf("# InterfaceBlock %v: Type=0x%08x TotalLength=%v len(Data)=%v LinkType=%v SnapLen=%v\n", count+1, ib.Type, ib.TotalLength, len(ib.Data), ib.LinkType, ib.SnapLen)
			if err = pw.Write(ib); err != nil {
				panic(err)
			}

		} else if epb, ok := block.(*pcapng2.EnhancedPacketBlock); ok {

			fmt.Printf("# EnhancedPacketBlock %v: Type=0x%08x TotalLength=%v len(Data)=%v\n", count+1, epb.Type, epb.TotalLength, len(epb.Data))
			if err = pw.Write(epb); err != nil {
				panic(err)
			}

		} else if gb, ok := block.(*pcapng2.GenericBlock); ok {

			fmt.Printf("# GenericBlock %v: Type=0x%08x TotalLength=%v len(Data)=%v\n", count+1, gb.Type, gb.TotalLength, len(gb.Data))
			if err = pw.Write(gb); err != nil {
				panic(err)
			}

		}
	}
}
