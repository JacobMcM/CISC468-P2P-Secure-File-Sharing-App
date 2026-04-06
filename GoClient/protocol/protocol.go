package protocol

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
)

type MessageType string

const (
	// HANDSHAKE          MessageType = "HANDSHAKE"
	EKE_1              MessageType = "EKE_1"
	EKE_2              MessageType = "EKE_2"
	EKE_3              MessageType = "EKE_3"
	EKE_4              MessageType = "EKE_4"
	STS_1              MessageType = "STS_1"
	STS_2              MessageType = "STS_2"
	STS_3              MessageType = "STS_3"
	// FILE_LIST_REQUEST  MessageType = "FILE_LIST_REQUEST"
	// FILE_LIST_RESPONSE MessageType = "FILE_LIST_RESPONSE"
	// FILE_REQUEST       MessageType = "FILE_REQUEST"
	// CONSENT_REQUEST    MessageType = "CONSENT_REQUEST"
	// CONSENT_RESPONSE   MessageType = "CONSENT_RESPONSE"
	// FILE_TRANSFER      MessageType = "FILE_TRANSFER"
	// KEY_ROTATION       MessageType = "KEY_ROTATION"
	// ERROR_MSG          MessageType = "ERROR_MSG"
)

// First decode incoming messages to this, then read type and cast json to more specific struct
type BaseMessage struct {
    Type MessageType `json:"type"`
}

type EKE1Message struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
    C1   []byte `json:"c1"`
}

type EKE2Message struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
    C2   []byte `json:"c2"`
    C3   []byte `json:"c3"`
}

type EKE3Message struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
    C4   []byte `json:"c4"`
}

type EKE4Message struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
    C5   []byte `json:"c5"`
}

type STS1Message struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
    Dh_public_key   []byte `json:"dh_public_key"`
}

type STS2Message struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
    Dh_public_key   []byte `json:"dh_public_key"`
    Encrypted_signature []byte `json:"encrypted_signature"`
}

type STS3Message struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
    Encrypted_signature []byte `json:"encrypted_signature"`
}

func BuildEKE1(from string, c1 []byte) ([]byte, error) {
    return json.Marshal(EKE1Message{
        Type: EKE_1,
        From: from,
        C1:   c1,
    })
}

func BuildEKE2(from string, c2, c3 []byte) ([]byte, error) {
    return json.Marshal(EKE2Message{
        Type: EKE_2,
        From: from,
        C2:   c2,
        C3:   c3,
    })
}

func BuildEKE3(from string, c4 []byte) ([]byte, error) {
    return json.Marshal(EKE3Message{
        Type: EKE_3,
        From: from,
        C4:   c4,
    })
}

func BuildEKE4(from string, c5 []byte) ([]byte, error) {
    return json.Marshal(EKE4Message{
        Type: EKE_4,
        From: from,
        C5:   c5,
    })
}

func BuildSTS1(from string, myDhValue []byte) ([]byte, error) {
    return json.Marshal(STS1Message{
        Type: STS_1,
        From: from,
        Dh_public_key: myDhValue,
    })
}

func BuildSTS2(from string, myDhValue, encryptedSignature []byte) ([]byte, error) {
	return json.Marshal(STS2Message{
		Type: STS_2,
		From: from,
        Dh_public_key: myDhValue,
		Encrypted_signature: encryptedSignature,
	})
}

func BuildSTS3(from string, encryptedSignature []byte) ([]byte, error) {
	return json.Marshal(STS3Message{
		Type: STS_3,
		From: from,
		Encrypted_signature: encryptedSignature,
	})
}




type Message interface {
    BaseMessage | EKE1Message | EKE2Message | EKE3Message | EKE4Message | STS1Message | STS2Message | STS3Message 
}

func ParseMessage[T Message](data []byte) (T, error) {
    var msg T
    err := json.Unmarshal(data, &msg)
    return msg, err
}

func sendMessage(conn net.Conn, msg []byte) error {
    length := uint32(len(msg))
    if err := binary.Write(conn, binary.BigEndian, length); err != nil {
        return err
    }
    _, err := conn.Write(msg)
    return err
}

func receiveMessage(conn net.Conn) ([]byte, error) {
    var length uint32
    if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
        return nil, err
    }
    buf := make([]byte, length)
    _, err := io.ReadFull(conn, buf)
    return buf, err
}