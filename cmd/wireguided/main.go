package main

import (
	"log"

	"github.com/korjwl1/wireguide/internal/daemon"
)

func main() {
	log.Println("WireGuide daemon starting...")
	if err := daemon.Run(); err != nil {
		log.Fatal("daemon error:", err)
	}
}
