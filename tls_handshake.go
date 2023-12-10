package main

import (
	"log"
)

type HandshakeType uint8

const (
	HelloRequest       HandshakeType  = iota // 0
	ClientHello                              // 1
	ServerHello                              // 2
	Certificate        = iota + 8            // 11
	ServerKeyExchange                        // 12
	CertificateRequest                       // 13
	ServerHelloDone                          // 14
	CertificateVerify                        // 15
	ClientKeyExchange                        // 16
	Finished           = iota + 8 + 3        // 20
	// 255
)

type ProtocolVersion struct {
	Major uint8 // 3 on TLS 1.2
	Minor uint8 // 3 on TLS 1.2
}

type Random struct {
	GmtUnixTime uint32
	RandomBytes byte[28]
}
type SessionId byte[32]

type ClientHello struct {
	ClientVersion      ProtocolVersion
	Random             Random
	SessionId          SessionId
	CipherSuites       uint16
	CompressionMethods uint8
	Extensions         uint16
}

type Handshake struct {
	MsgType HandshakeType
	Length  uint32 // uint24
	Body    ClientHello
}

func main() {
	log.Println(Finished)
	// log.Println("Connecting ...")
	// // サーバーに接続
	// conn, err := net.Dial("tcp", "1.1.1.1:443")
	// if err != nil {
	// 	fmt.Println("Error connecting to the server:", err)
	// 	return
	// }
	// defer conn.Close()
}
