package main

import (
	"encrypt"
	"local"
	"log"
	"server"
)

func main() {
	// enable on your client
	// StartClient()

	// enable on your server
	// StartServer()
}

func StartClient() {
	localC, err := local.New(&encrypt.None{}, "localPort", "dstAddr:dstPort")
	if err != nil {
		log.Fatalln(err)
	}

	localC.Serve()
}

func StartServer() {
	serverS, err := server.New(&encrypt.None{}, "listenPort")
	if err != nil {
		log.Fatalln(err)
	}
	serverS.Serve()
}
