package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
)

type ProtocolVersion struct {
	Major uint8
	Minor uint8
}

type ContentType uint8

const (
	ChangeCipherSpec ContentType = 20 + iota
	Alert
	Handshake
	ApplicationData
	// 255
)

type TLSPlaintext struct {
	Type    ContentType
	Version ProtocolVersion
	Length  uint16
	Opaque  []byte
}

func encodeTLSPlaintext(payload TLSPlaintext) ([]byte, error) {
	buf := make([]byte, 4+len(payload.Opaque))
	buf[0] = byte(payload.Type)
	buf[1] = byte(payload.Version.Major)
	buf[2] = byte(payload.Version.Minor)
	binary.BigEndian.PutUint16(buf[3:5], payload.Length)
	copy(buf[5:], payload.Opaque)

	return buf, nil
}

func main() {
	log.Println("Connecting ...")
	// サーバーに接続
	conn, err := net.Dial("tcp", "1.1.1.1:443")
	if err != nil {
		fmt.Println("Error connecting to the server:", err)
		return
	}
	defer conn.Close()

	// ペイロードの組み立て
	log.Println("Create payload ...")
	payload := TLSPlaintext{
		Type: Handshake,
		Version: ProtocolVersion{
			Major: 3,
			Minor: 3,
		},
		Length: 10,
		Opaque: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}
	payloadByte, err := encodeTLSPlaintext(payload)
	payloadByteHex := hex.EncodeToString(payloadByte)
	log.Printf("payloadByte: %s", payloadByteHex)
	if err != nil {
		fmt.Println("Fail to encode TLSPlaintext", err)
		return
	}

	// サーバーにメッセージを送信
	log.Println("Sending ...")
	_, err = conn.Write(payloadByte)
	if err != nil {
		fmt.Println("Error sending message to the server:", err)
		return
	}

	// サーバーからの応答を受信
	log.Println("Receiving ...")
	buffer := make([]byte, 1024)
	count, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading server response:", err)
		return
	}

	fmt.Println("Server response:", string(buffer[:count]))
}
