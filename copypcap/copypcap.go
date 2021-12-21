package main

import (
	"fmt"
	"io"
	"os"
	"github.com/RajeshGottlieb/go/pcap"
)

func main() {

	if len(os.Args) != 3 {
		fmt.Printf("usage: %v <input-pcap> <output-pcap>\n", os.Args[0])
		return
	}

	rfh, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer rfh.Close()

	pr, err := pcap.Reader(rfh)
	if err != nil {
		panic(err)
	}

	wfh, err := os.Create(os.Args[2])
	if err != nil {
		panic(err)
	}
	defer wfh.Close()

	pw, err := pcap.Writer(wfh)
	if err != nil {
		panic(err)
	}

	for count := 0; true; count++ {

		ts, pkt, err := pr.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}

		err = pw.Write(ts, pkt)
		if err != nil {
			panic(err)
		}

	}
}
