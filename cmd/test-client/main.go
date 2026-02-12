package main

import (
	"fmt"
	"log"
	"os"

	nwep "github.com/usenwep/nwep-go"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: test-client <web://url/path>\n")
		os.Exit(1)
	}
	url := os.Args[1]

	if err := nwep.Init(); err != nil {
		log.Fatal("init:", err)
	}

	nwep.SetLogLevel(nwep.LogWarn)
	nwep.SetLogStderr(true)

	parsed, err := nwep.URLParse(url)
	if err != nil {
		log.Fatal("parse url:", err)
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}

	kp, err := nwep.GenerateKeypair()
	if err != nil {
		log.Fatal("keygen:", err)
	}
	defer kp.Clear()

	client, err := nwep.NewClient(kp)
	if err != nil {
		log.Fatal("client new:", err)
	}

	if err := client.Connect(url); err != nil {
		log.Fatal("connect:", err)
	}

	resp, err := client.Get(path)
	if err != nil {
		log.Fatal("get:", err)
	}

	fmt.Println(resp.Status)
	fmt.Println(string(resp.Body))

	client.Close()
}
