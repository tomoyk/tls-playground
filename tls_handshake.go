package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	log.Println("Connecting ...")
	// サーバーに接続
	conn, err := net.Dial("tcp", "1.1.1.1:443")
	if err != nil {
		fmt.Println("Error connecting to the server:", err)
		return
	}
	defer conn.Close()
}
