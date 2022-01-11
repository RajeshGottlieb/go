This go module copies a pcapng file

Example usage:
    copypcapng input.pcapng output.pcapng

Create a directory for the module

    mkdir copypcapng
    cd copypcapng

Initialize the module. This will create the go.mod file.

    go mod init github.com/RajeshGottlieb/go/copypcapng

Edit go file

    vi copypcapng.go

Tell go that the pcapng module is local (go.mod is updated)

    go mod edit -replace example.com/pcapng2=../pcapng2

Download and verify imported modules.

    go mod tidy

Run the code

    go run copypcapng.go ntp.pcapng out.pcapng

Compiled the code into a standalone binary and run it

    go build .
    ./copypcapng ntp.pcapng out.pcapng
