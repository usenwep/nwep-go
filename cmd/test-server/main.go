package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	nwep "nwep-go"
)

const defaultKeyFile = "server.key"

// loadOrGenerateKeypair loads a keypair from a hex-encoded seed file,
// or generates a new one and saves it.
func loadOrGenerateKeypair(path string) (*nwep.Keypair, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		// Existing key file — decode the 32-byte seed.
		var seed [32]byte
		n, err := hex.Decode(seed[:], trimNewline(data))
		if err != nil || n != 32 {
			return nil, fmt.Errorf("invalid key file %s: expected 64 hex chars", path)
		}
		return nwep.KeypairFromSeed(seed)
	}

	if !os.IsNotExist(err) {
		return nil, err
	}

	// No key file — generate and save.
	kp, err := nwep.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	seed := kp.Seed()
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed[:])+"\n"), 0600); err != nil {
		kp.Clear()
		return nil, fmt.Errorf("saving key file: %w", err)
	}
	return kp, nil
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func main() {
	if err := nwep.Init(); err != nil {
		log.Fatal("init:", err)
	}

	nwep.SetLogLevel(nwep.LogWarn)
	nwep.SetLogStderr(true)

	keyFile := defaultKeyFile
	if v := os.Getenv("NWEP_KEY_FILE"); v != "" {
		keyFile = v
	}

	kp, err := loadOrGenerateKeypair(keyFile)
	if err != nil {
		log.Fatal("keypair:", err)
	}
	defer kp.Clear()

	nid, _ := kp.NodeID()
	log.Printf("node id: %s", nid)

	router := nwep.NewRouter()
	router.HandleFunc("/hello", func(w *nwep.ResponseWriter, r *nwep.Request) {
		w.Respond("ok", []byte("hello from nwep-go"))
	})

	addr := ":6937"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	opts := []nwep.ServerOption{
		nwep.WithOnConnect(func(c *nwep.Conn) {
			log.Printf("connected: %s", c.NodeID())
		}),
		nwep.WithOnDisconnect(func(c *nwep.Conn, code int) {
			log.Printf("disconnected: %s (code %d)", c.NodeID(), code)
		}),
	}

	var srv *nwep.Server
	port := 6937
	if len(os.Args) > 1 {
		// Explicit addr — try once, no retry.
		srv, err = nwep.NewServer(addr, kp, router, opts...)
		if err != nil {
			log.Fatal("server new:", err)
		}
	} else {
		// Default port — retry on bind failure, incrementing port.
		for attempts := 0; attempts < 100; attempts++ {
			addr = fmt.Sprintf(":%d", port)
			srv, err = nwep.NewServer(addr, kp, router, opts...)
			if err == nil {
				break
			}
			port++
		}
		if srv == nil {
			log.Fatalf("could not bind any port in range %d-%d", 6937, port-1)
		}
	}

	url := srv.URL("/hello")
	fmt.Fprintf(os.Stderr, "listening on %s\n", srv.Addr())
	fmt.Println(url) // Print URL to stdout for the client to read

	if err := srv.Run(); err != nil {
		log.Fatal("server run:", err)
	}
}
