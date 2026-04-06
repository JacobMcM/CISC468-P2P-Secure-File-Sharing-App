package transport

import (
	"GoClient/auth"
	"GoClient/discovery"
	"GoClient/session"
	"fmt"
	"net"
)

func ConnectToPeer(peer *discovery.Peer, selfName, password string) (*session.SecureSession, error) {
	addr := net.JoinHostPort(peer.IP, fmt.Sprintf("%d", peer.Port))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	framed := session.NewFramedConn(conn)
	secureSession, err := auth.RunClientSideDhEKE(framed, password, selfName, peer.Name); if err != nil {
		return nil, err
	}

	fmt.Printf("Success connecting to: %s\n", peer.Name)
	return secureSession, nil
}