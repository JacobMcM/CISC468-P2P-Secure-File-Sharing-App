/*
This file represents our messaging protocol.
Valid messages are typed and enumerated below.
A constructor function is provided for each message, converting it to valid json for network transmission.
*/

package protocol

import (
	file "GoClient/file_manager"
	"encoding/json"
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
	FILE_LIST_REQUEST  MessageType = "FILE_LIST_REQUEST"
	FILE_LIST_RESPONSE MessageType = "FILE_LIST_RESPONSE"
	FILE_REQUEST       MessageType = "FILE_REQUEST"
	CONSENT_REQUEST    MessageType = "CONSENT_REQUEST"
	CONSENT_RESPONSE   MessageType = "CONSENT_RESPONSE"
	FILE_TRANSFER      MessageType = "FILE_TRANSFER"
	// KEY_ROTATION       MessageType = "KEY_ROTATION"
	ERROR_MSG          MessageType = "ERROR_MSG"
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

type FileListRequestMessage struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
}

type FileListResponseMessage struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
    Files []*file.FileInfo `json:"files"`
}

type FileRequestMessage struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
    Filename string `json:"filename"`
}

type ConsentRequestMessage struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
    Filename string `json:"filename"`
    Filesize int64 `json:"filesize"`
}

type ConsentResponseMessage struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
    Filename string `json:"filename"`
    Accepted bool `json:"accepted"`
}

type FileTransferMessage struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
    Filename string `json:"filename"`
    Data []byte `json:"data"`
    Hash []byte `json:"hash"`
    Signature []byte `json:"signature"`
    OriginalOwner string `json:"original_owner"`
}

type ErrorMessage struct {
    Type MessageType `json:"type"`
    From string `json:"from"`
    Message string `json:"message"`
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

func BuildFileListRequest(from string) ([]byte, error) {
    return json.Marshal(FileListRequestMessage{
        Type: FILE_LIST_REQUEST,
        From: from,
    })
}

func BuildFileListResponse(from string, files []*file.FileInfo) ([]byte, error) {
    return json.Marshal(FileListResponseMessage{
        Type: FILE_LIST_RESPONSE,
        From: from,
        Files: files,
    })
}

func BuildFileRequest(from, filename string) ([]byte, error) {
    return json.Marshal(FileRequestMessage{
        Type: FILE_REQUEST,
        From: from,
        Filename: filename,
    })
}

func BuildConsentRequest(from, filename string, filesize int64) ([]byte, error) {
    return json.Marshal(ConsentRequestMessage{
        Type: CONSENT_REQUEST,
        From: from,
        Filename: filename,
        Filesize: filesize,
    })
}

func BuildConsentResponse(from, filename string, accepted bool) ([]byte, error) {
    return json.Marshal(ConsentResponseMessage{
        Type: CONSENT_RESPONSE,
        From: from,
        Filename: filename,
        Accepted: accepted,
    })
}

func BuildFileTransfer(from, filename, original_owner string, hash, signature, data []byte) ([]byte, error) {
    return json.Marshal(FileTransferMessage{
        Type: FILE_TRANSFER,
        From: from,
        Filename: filename,
        Data: data,
        Hash: hash,
        Signature: signature,
        OriginalOwner: original_owner,
    })
}

func BuildErrorMessage(from, message string) ([]byte, error) {
    return json.Marshal(ErrorMessage{
        Type: ERROR_MSG,
        From: from,
        Message: message,
    })
}

type Message interface {
    BaseMessage | EKE1Message | EKE2Message | EKE3Message | EKE4Message | STS1Message | STS2Message | STS3Message | FileListRequestMessage | FileListResponseMessage | FileRequestMessage | FileTransferMessage | ErrorMessage | ConsentRequestMessage | ConsentResponseMessage
}

func ParseMessage[T Message](data []byte) (T, error) {
    var msg T
    err := json.Unmarshal(data, &msg)
    return msg, err
}