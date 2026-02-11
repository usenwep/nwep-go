package main

import (
	"fmt"
	"log"
	"os"

	nwep "nwep-go"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: test-client <web://url>\n")
		os.Exit(1)
	}
	url := os.Args[1]

	if err := nwep.Init(); err != nil {
		log.Fatal("init:", err)
	}

	nwep.SetLogLevel(nwep.LogWarn)
	nwep.SetLogStderr(true)

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

	resp, err := client.Get("/hello")
	if err != nil {
		log.Fatal("get:", err)
	}

	fmt.Println(resp.Status)
	fmt.Println(string(resp.Body))

	client.Close()
}
