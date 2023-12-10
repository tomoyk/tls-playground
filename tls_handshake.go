package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"
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
	RandomBytes [28]byte
}
type SessionId [32]byte

type CipherSuite [2]uint8

const (
	TLS_NULL_WITH_NULL_NULL             CipherSuite = [2]uint8{0x00, 0x00}
	TLS_RSA_WITH_NULL_MD5               CipherSuite = [2]uint8{0x00, 0x01}
	TLS_RSA_WITH_NULL_SHA               CipherSuite = [2]uint8{0x00, 0x02}
	TLS_RSA_WITH_NULL_SHA256            CipherSuite = [2]uint8{0x00, 0x3B}
	TLS_RSA_WITH_RC4_128_MD5            CipherSuite = [2]uint8{0x00, 0x04}
	TLS_RSA_WITH_RC4_128_SHA            CipherSuite = [2]uint8{0x00, 0x05}
	TLS_RSA_WITH_3DES_EDE_CBC_SHA       CipherSuite = [2]uint8{0x00, 0x0A}
	TLS_RSA_WITH_AES_128_CBC_SHA        CipherSuite = [2]uint8{0x00, 0x2F}
	TLS_RSA_WITH_AES_256_CBC_SHA        CipherSuite = [2]uint8{0x00, 0x35}
	TLS_RSA_WITH_AES_128_CBC_SHA256     CipherSuite = [2]uint8{0x00, 0x3C}
	TLS_RSA_WITH_AES_256_CBC_SHA256     CipherSuite = [2]uint8{0x00, 0x3D}
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA    CipherSuite = [2]uint8{0x00, 0x0D}
	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA    CipherSuite = [2]uint8{0x00, 0x10}
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA   CipherSuite = [2]uint8{0x00, 0x13}
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA   CipherSuite = [2]uint8{0x00, 0x16}
	TLS_DH_DSS_WITH_AES_128_CBC_SHA     CipherSuite = [2]uint8{0x00, 0x30}
	TLS_DH_RSA_WITH_AES_128_CBC_SHA     CipherSuite = [2]uint8{0x00, 0x31}
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA    CipherSuite = [2]uint8{0x00, 0x32}
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA    CipherSuite = [2]uint8{0x00, 0x33}
	TLS_DH_DSS_WITH_AES_256_CBC_SHA     CipherSuite = [2]uint8{0x00, 0x36}
	TLS_DH_RSA_WITH_AES_256_CBC_SHA     CipherSuite = [2]uint8{0x00, 0x37}
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA    CipherSuite = [2]uint8{0x00, 0x38}
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA    CipherSuite = [2]uint8{0x00, 0x39}
	TLS_DH_DSS_WITH_AES_128_CBC_SHA256  CipherSuite = [2]uint8{0x00, 0x3E}
	TLS_DH_RSA_WITH_AES_128_CBC_SHA256  CipherSuite = [2]uint8{0x00, 0x3F}
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 CipherSuite = [2]uint8{0x00, 0x40}
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 CipherSuite = [2]uint8{0x00, 0x67}
	TLS_DH_DSS_WITH_AES_256_CBC_SHA256  CipherSuite = [2]uint8{0x00, 0x68}
	TLS_DH_RSA_WITH_AES_256_CBC_SHA256  CipherSuite = [2]uint8{0x00, 0x69}
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 CipherSuite = [2]uint8{0x00, 0x6A}
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 CipherSuite = [2]uint8{0x00, 0x6B}
	TLS_DH_anon_WITH_RC4_128_MD5        CipherSuite = [2]uint8{0x00, 0x18}
	TLS_DH_anon_WITH_3DES_EDE_CBC_SHA   CipherSuite = [2]uint8{0x00, 0x1B}
	TLS_DH_anon_WITH_AES_128_CBC_SHA    CipherSuite = [2]uint8{0x00, 0x34}
	TLS_DH_anon_WITH_AES_256_CBC_SHA    CipherSuite = [2]uint8{0x00, 0x3A}
	TLS_DH_anon_WITH_AES_128_CBC_SHA256 CipherSuite = [2]uint8{0x00, 0x6C}
	TLS_DH_anon_WITH_AES_256_CBC_SHA256 CipherSuite = [2]uint8{0x00, 0x6D}
)

type ClientHello struct {
	ClientVersion      ProtocolVersion
	Random             Random
	SessionId          SessionId
	CipherSuites       []CipherSuite
	CompressionMethods uint8
	Extensions         uint16
}

type HandshakeProtocol struct {
	MsgType HandshakeType
	Length  uint32 // uint24
	Body    ClientHello
}

func serializeHandshakeProtocol(handshake HandshakeProtocol) ([]byte, error) {
	// Buffer to hold the serialized data
	buffer := new(bytes.Buffer)

	// Write MsgType to the buffer
	err := binary.Write(buffer, binary.BigEndian, handshake.MsgType)
	if err != nil {
		return nil, err
	}

	// Write Length to the buffer as uint24 (3 bytes)
	err = binary.Write(buffer, binary.BigEndian, uint8((handshake.Length>>16)&0xFF))
	if err != nil {
		return nil, err
	}
	err = binary.Write(buffer, binary.BigEndian, uint8((handshake.Length>>8)&0xFF))
	if err != nil {
		return nil, err
	}
	err = binary.Write(buffer, binary.BigEndian, uint8(handshake.Length&0xFF))
	if err != nil {
		return nil, err
	}

	// Serialize the ClientHello struct into the buffer
	clientHelloBytes, err := serializeClientHello(handshake.Body)
	if err != nil {
		return nil, err
	}

	// Write the serialized ClientHello to the buffer
	_, err = buffer.Write(clientHelloBytes)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func serializeClientHello(clientHello ClientHello) ([]byte, error) {
	// Buffer to hold the serialized data
	buffer := new(bytes.Buffer)

	// Serialize each field of the ClientHello struct into the buffer

	err := binary.Write(buffer, binary.BigEndian, clientHello.ClientVersion)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buffer, binary.BigEndian, clientHello.Random)
	if err != nil {
		return nil, err
	}

	// Serialize SessionId
	_, err = buffer.Write(clientHello.SessionId[:])
	if err != nil {
		return nil, err
	}

	// Serialize CipherSuites
	for _, suite := range clientHello.CipherSuites {
		err = binary.Write(buffer, binary.BigEndian, suite)
		if err != nil {
			return nil, err
		}
	}

	// Serialize CompressionMethods
	err = binary.Write(buffer, binary.BigEndian, clientHello.CompressionMethods)
	if err != nil {
		return nil, err
	}

	// Serialize Extensions
	err = binary.Write(buffer, binary.BigEndian, clientHello.Extensions)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func main() {
	log.Println("Started")
	// timestamp
	dt := time.Now()
	log.Println(dt)
	unix := dt.Unix()
	log.Println(unix)

	// サーバーに接続
	log.Println("Connecting ...")
	conn, err := net.Dial("tcp", "1.1.1.1:443")
	if err != nil {
		fmt.Println("Error connecting to the server:", err)
		return
	}
	defer conn.Close()

	// ペイロードの組み立て
	log.Println("Create payload ...")
	ch := ClientHello{
		ClientVersion: ProtocolVersion{
			Major: 3,
			Minor: 3,
		},
		Random: Random{
			GmtUnixTime: unix,
			RandomBytes: []byte("abcdefghijklmnopqrstuvwxyz12"),
		},
		SessionId:          SessionId{0, 0, 0, 0, 0, 0, 0, 0},
		CipherSuites:       []CipherSuite{TLS_RSA_WITH_NULL_MD5, TLS_RSA_WITH_RC4_128_SHA},
		CompressionMethods: 0,
		Extensions:         0,
	}
	hp := HandshakeProtocol{
		MsgType: HelloRequest,
		Length:  uint32(len(clientHello.CipherSuites) + len(clientHello.SessionId) + 39), // Adjust the length based on the actual structure
		Body:    ch,
	}
	serializedData, err := serializeHandshakeProtocol(hp)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	// Debug
	payloadByteHex := hex.EncodeToString(serializedData)
	log.Printf("payloadByte: %s", payloadByteHex)

	// サーバーにメッセージを送信
	log.Println("Sending ...")
	_, err = conn.Write(serializedData)
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
