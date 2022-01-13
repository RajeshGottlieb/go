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

		} else if b, ok := block.(*pcapng.EnhancedPacketBlock); ok {

			fmt.Printf("# EnhancedPacketBlock %v: Type=0x%08x TotalLength=%v\n", count+1, b.Type, b.TotalLength)
			if err = pw.Write(b); err != nil {
				panic(err)
			}

		} else if b, ok := block.(*pcapng.GenericBlock); ok {

			fmt.Printf("# GenericBlock %v: Type=0x%08x TotalLength=%v len(Data)=%v\n", count+1, b.Type, b.TotalLength, len(b.Data))
			if err = pw.Write(b); err != nil {
				panic(err)
			}

		}
	}
}
