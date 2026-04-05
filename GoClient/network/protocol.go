package network

type MessageType string

const (
	HANDSHAKE          MessageType = "HANDSHAKE"
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
	KEY_ROTATION       MessageType = "KEY_ROTATION"
	ERROR_MSG          MessageType = "ERROR_MSG"
)

type Message struct {
	Type    MessageType
	Payload []byte
}
