/*
SecureSession wraps a FramedConn, ensuring all messages are encrypted under
a session key before enetering the network. It is created once a key establshment protocol has
been run between 2 peers
*/

package session

import (
	"GoClient/crypto"
	"crypto/rsa"
)

type SecureSession struct {
	conn       *FramedConn
	sessionKey []byte
	PeerName   string
	SelfName string
	PeerPubKey *rsa.PublicKey
}

func NewSecureSession(conn *FramedConn, sessionKey []byte, peerName string, selfName string, peerPubKey *rsa.PublicKey) *SecureSession {
	return &SecureSession{conn: conn, sessionKey: sessionKey, PeerName: peerName, SelfName: selfName, PeerPubKey: peerPubKey}
}

func (s *SecureSession) Send(msg []byte) error {
	ciphertext, err := crypto.Encrypt(s.sessionKey, msg); if err != nil {
		return err
	}
	return s.conn.Send(ciphertext)
}

func (s *SecureSession) Recv() ([]byte, error) {
    ciphertext, err := s.conn.Recv()
    if err != nil {
        return nil, err
    }
    return crypto.Decrypt(s.sessionKey, ciphertext)
}

func (s *SecureSession) Close() (error) {
	return s.conn.Close()
}
