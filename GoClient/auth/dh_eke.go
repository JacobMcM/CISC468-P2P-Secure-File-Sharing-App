package auth

import (
	"GoClient/crypto"
	"GoClient/discovery"
	"GoClient/protocol"
	"GoClient/session"
	"fmt"
)

func RunClientSideDhEKE(conn *session.FramedConn, password, selfName, peerName string) (*session.SecureSession, error) {
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
		return nil, err
	}

	eke2Message, err := protocol.ParseMessage[protocol.EKE2Message](eke2raw)
	if err != nil {
		return nil, err
	}

	p2Bytes, err := p.DecryptW(eke2Message.C2)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	conn.Send(eke3Message)
	fmt.Printf("Sent C4 to peer, Length: %d\n", len(C4))

	eke4raw, err := conn.Recv()
	if err != nil {
		return nil, err
	}

	eke4Message, err := protocol.ParseMessage[protocol.EKE4Message](eke4raw)

	P5, err := p.DecryptK(eke4Message.C5); if err != nil {
		return nil, err
	}

	receivedRA := P5[:16]
	peerPubKeyB64 := P5[16:]
	fmt.Printf("\n\n\n\nPUBKEY: %s\n\n\n\n", string(peerPubKeyB64))

	peerPubKey, err := crypto.PemToPublicKey(string(peerPubKeyB64)); if err != nil {
		return nil, err
	}

	p.ValidateRA(receivedRA)

	secureSession := session.NewSecureSession(conn, p.K, peerName, selfName, peerPubKey)

	err = discovery.AddPeerRecord("keys/peer_pub_keys.json", peerName, peerPubKey); if err != nil {
		return nil, err
	}

	return secureSession, nil
}

func RunServerSideDhEKE(conn *session.FramedConn, init_message protocol.EKE1Message, password, selfName string) (*session.SecureSession, error) {
	p, err := crypto.NewPakeState(password, init_message.From, selfName); if err != nil {
		return nil, err
	}

	P1_bytes, err := p.DecryptW(init_message.C1); if err != nil { 
		panic(fmt.Sprintf("decrypt C1 failed: %v", err)) 
	}

	p.GenerateB()
	p.GenerateRB()

	p.DeriveK(P1_bytes)

	C2, C3 := p.BuildC2_C3()

	eke2Message, _ := protocol.BuildEKE2(selfName, C2, C3)

	conn.Send(eke2Message)

	fmt.Printf("Sent C2, C3 to Peer! Length C2: %d, Length C3: %d\n", len(C2), len(C3))

	eke3Raw, err := conn.Recv()
	if err != nil {
		panic(fmt.Sprintf("Recv eke3 failed: %v", err))
	}

	eke3Message, err := protocol.ParseMessage[protocol.EKE3Message](eke3Raw)
	if err != nil {
		panic("Could not cast to EKE3Message")
	}


	P4_bytes, _ := p.DecryptK(eke3Message.C4);
	rA := P4_bytes[:16]
	receivedRB := P4_bytes[16:32]
	fmt.Printf("\n\n\n\nRECEIVED RB: %s\n\n\n", receivedRB)

	if p.ValidateRB(receivedRB) {
		fmt.Printf("rB Validated!\n")
	} else {
		fmt.Printf("rB validation failed!!!\n")
		return nil, fmt.Errorf("Challenge validation failed, connection with peer dropped")
	}

	peerPubKeyPEM := P4_bytes[32:]

	peerPubKey, err := crypto.PemToPublicKey(string(peerPubKeyPEM)); if err != nil {
		return nil, err
	}

	C5, err := p.BuildC5(rA)
	eke4Message, err := protocol.BuildEKE4(selfName, C5)

	if err != nil {
		panic("Could not build EKE4Message")
	}

	conn.Send(eke4Message)
	fmt.Printf("Sent C5 to Peer! Length: %d\n", len(C5));

	discovery.AddPeerRecord("keys/peer_pub_keys.json", init_message.From, peerPubKey)

	return session.NewSecureSession(conn, p.K, init_message.From, selfName, peerPubKey), nil
}