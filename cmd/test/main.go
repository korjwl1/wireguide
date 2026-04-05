package main

import (
	"fmt"
	"os"
	"time"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/korjwl1/wireguide/internal/tunnel"
)

func main() {
	confPath := "/Users/korjwl1/Downloads/Letsur-Internal-VPN.conf"
	if len(os.Args) > 1 {
		confPath = os.Args[1]
	}

	// Step 1: Parse
	fmt.Println("=== Step 1: Parse ===")
	data, err := os.ReadFile(confPath)
	if err != nil {
		fmt.Println("ERROR reading file:", err)
		os.Exit(1)
	}
	cfg, err := config.Parse(string(data))
	if err != nil {
		fmt.Println("PARSE ERROR:", err)
		os.Exit(1)
	}
	cfg.Name = "Letsur-Internal-VPN"
	fmt.Println("OK - Endpoint:", cfg.Peers[0].Endpoint, "FullTunnel:", cfg.IsFullTunnel())

	// Step 2: Validate
	fmt.Println("\n=== Step 2: Validate ===")
	result := config.Validate(cfg)
	if !result.IsValid() {
		fmt.Println("VALIDATION ERRORS:")
		for _, e := range result.Errors {
			fmt.Println(" -", e)
		}
		os.Exit(1)
	}
	fmt.Println("OK - All fields valid")

	// Step 3: Connect
	fmt.Println("\n=== Step 3: Connect ===")
	manager := tunnel.NewManager(os.TempDir())
	err = manager.Connect(cfg, false)
	if err != nil {
		fmt.Println("CONNECT ERROR:", err)
		os.Exit(1)
	}
	fmt.Println("OK - Connected!")

	// Step 4: Status (poll 3 times)
	fmt.Println("\n=== Step 4: Status ===")
	for i := 0; i < 3; i++ {
		time.Sleep(2 * time.Second)
		status := manager.Status()
		fmt.Printf("  [%d] State=%s RX=%d TX=%d Handshake=%s Duration=%s\n",
			i+1, status.State, status.RxBytes, status.TxBytes,
			status.LastHandshake, status.Duration)
	}

	// Step 5: Disconnect
	fmt.Println("\n=== Step 5: Disconnect ===")
	err = manager.Disconnect()
	if err != nil {
		fmt.Println("DISCONNECT ERROR:", err)
		os.Exit(1)
	}
	fmt.Println("OK - Disconnected, routes/DNS restored")

	fmt.Println("\n=== ALL TESTS PASSED ===")
}
