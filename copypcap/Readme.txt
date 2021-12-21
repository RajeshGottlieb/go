This go module is for testing the pcap module.
It copies a pcap by reading one and writing another.

Example usage:
    copypcap input.pcap output.pcap

Initialize the module. This will create the go.mod file.

    go mod init copypcap

Download and verify imported modules.

    go mod tidy

Run the code

    go run copypcap.go input.pcap output.pcap

Compiled the code into a standalone binary and run it

    go build .
    ./copypcap input.pcap output.pcap
