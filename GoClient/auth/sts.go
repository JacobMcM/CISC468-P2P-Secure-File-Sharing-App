package auth

import (
	"GoClient/crypto"
	"GoClient/protocol"
	"GoClient/session"
	"fmt"
)

func RunClientSideSTS(conn *session.FramedConn, password, selfName, peerName string) (*session.SecureSession, error) {
	p, err := crypto.NewPakeState(password, selfName, peerName); if err != nil {
		return nil, err
	}

	p.GenerateA()
	p.GenerateRA()

	C1 := p.BuildC1()

	eke1Message, _ := protocol.BuildEKE1(selfName, C1)
	conn.Send(eke1Message)
	fmt.Printf("Sent EKE1 to Peer!")

	// Receive C2 = enc_w(alpha^b), C3 = enc_K(r_b)
	eke2raw, err := conn.Recv()
	if err != nil {
		panic(fmt.Sprintf("Recv C2 failed: %v", err))
	}

	eke2Message, err := protocol.ParseMessage[protocol.EKE2Message](eke2raw)
	if err != nil {
		panic("FAILED TO PARSE EKE2MESSAGE")
	}

	p2Bytes, err := p.DecryptW(eke2Message.C2)
	if err != nil {
		panic("fialed to decrypt p2")
	}

	p.DeriveK(p2Bytes)
	fmt.Printf("MY KEY: %s", p.K)

	p3Bytes, _ := p.DecryptK(eke2Message.C3);
	p.GenerateRA();

	C4, err := p.BuildC4(p3Bytes); if err != nil {
		return nil, err
	}

	eke3Message, err := protocol.BuildEKE3(selfName, C4)
	if err != nil {
		panic("FAILED TO BUILD EKE3")
	}

	conn.Send(eke3Message)
	fmt.Printf("Sent C4 to peer, Length: %d\n", len(C4))

	// Receive server's challenge response and verify
	eke4raw, err := conn.Recv()
	if err != nil {
		panic("Failed to recv eke4")
	}

	eke4Message, err := protocol.ParseMessage[protocol.EKE4Message](eke4raw)

	receivedRA, _ := p.DecryptK(eke4Message.C5);

	p.ValidateRA(receivedRA)

	secureSession := session.NewSecureSession(conn, p.K, peerName)

	return secureSession, nil
}

// func RunServerSideSTS(conn *session.FramedConn, init_message protocol.STS1Message, selfName string) (*session.SecureSession, error) {
// 	s, err := crypto.NewStsState(init_message.From); if err != nil {
// 		return nil, err
// 	}
// 	return session.NewSecureSession(conn, p.K, init_message.From), nil
// }