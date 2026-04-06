package session

import (
	"GoClient/crypto"
	"fmt"
)

type SecureSession struct {
	conn       *FramedConn
	sessionKey []byte
	peerName   string
}

func NewSecureSession(conn *FramedConn, sessionKey []byte, peerName string) *SecureSession {
	return &SecureSession{conn: conn, sessionKey: sessionKey, peerName: peerName}
}

func (s *SecureSession) Send(msg []byte) error {
	ciphertext, err := crypto.Encrypt(s.sessionKey, msg); if err != nil {
		return err
	}
	return s.conn.Send(ciphertext)
}

func (s *SecureSession) PrintPrivateKeyLmao() {
	fmt.Printf("\n\n%s", s.sessionKey)
}