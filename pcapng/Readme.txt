This go module is used read pcapng files

Create a directory for the module

    mkdir pcapng
    cd pcapng

Initialize the module. This will create the go.mod file.

    go mod init github.com/RajeshGottlieb/go/pcapng

Edit go file

    vi pcapng.go

Download and verify imported modules.

    go mod tidy

Run the code

    go run .

Compiled the code into a standalone binary

    go build .
