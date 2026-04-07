package auth

import (
	"GoClient/crypto"
	"GoClient/protocol"
	"GoClient/session"
	"fmt"
)

func RunClientSideSTS(conn *session.FramedConn, selfName, peerName string) (*session.SecureSession, error) {
	s, err := crypto.NewStsState(peerName); if err != nil {
		return nil, err
	}
	fmt.Println("STS STATE INIT")

	myDhValue, err := s.BuildSTSMessage1Values(); if err != nil {
		return nil, err
	}

	fmt.Println("DH INIT")
	stsMessage1, err := protocol.BuildSTS1(selfName, myDhValue); if err != nil {
		return nil, err
	}

	conn.Send(stsMessage1)

	fmt.Println("M1 SENT")
	sts2raw, err := conn.Recv(); if err != nil {
		return nil, err
	}

	fmt.Println("M2 RECV")
	stsMessage2, err := protocol.ParseMessage[protocol.STS2Message](sts2raw); if err != nil {
		return nil, err
	}

	err = s.DeriveK(stsMessage2.Dh_public_key); if err != nil {
		return nil, err
	}

	plaintextSignature, err := s.DecryptK(stsMessage2.Encrypted_signature); if err != nil {
		return nil, err
	}


	err = s.VerifyReceivedSignature(stsMessage2.Dh_public_key, plaintextSignature); if err != nil {
		return nil, err
	}

	_, encryptedSignature, err := s.BuildSTSMessageValues(stsMessage2.Dh_public_key); if err != nil {
		return nil, err
	}

	stsMessage3, err := protocol.BuildSTS3(selfName, encryptedSignature); if err != nil {
		return nil, err
	}

	conn.Send(stsMessage3)

	fmt.Println("M3 SENT")
	return session.NewSecureSession(conn, s.K, peerName, selfName, s.PeerPubKey), nil
}

func RunServerSideSTS(conn *session.FramedConn, init_message protocol.STS1Message, selfName string) (*session.SecureSession, error) {
	s, err := crypto.NewStsState(init_message.From); if err != nil {
		return nil, err
	}

	err = s.DeriveK(init_message.Dh_public_key); if err != nil {
		return nil, err
	}

	myDhValue, encryptedSignature, err := s.BuildSTSMessageValues(init_message.Dh_public_key); if err != nil {
		return nil, err
	}

	stsMessage2, err := protocol.BuildSTS2(selfName, myDhValue, encryptedSignature); if err != nil {
		return nil, err
	}

	fmt.Printf("K: %s", s.K)

	conn.Send(stsMessage2)

	// Receive C2 = enc_w(alpha^b), C3 = enc_K(r_b)
	sts3raw, err := conn.Recv(); if err != nil {
		return nil, err
	}

	stsMessage3, err := protocol.ParseMessage[protocol.STS3Message](sts3raw); if err != nil {
		return nil, err
	}

	plaintextSignature, err := s.DecryptK(stsMessage3.Encrypted_signature); if err != nil {
		return nil, err
	}

	err = s.VerifyReceivedSignature(init_message.Dh_public_key, plaintextSignature); if err != nil {
		return nil, err
	}

	return session.NewSecureSession(conn, s.K, init_message.From, selfName, s.PeerPubKey), nil
}