package transport

import (
	"GoClient/auth"
	"GoClient/protocol"
	"GoClient/session"
	"encoding/json"
	"fmt"
	"log"
	"net"
)

func StartTCPServer(port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	log.Println("TCP server listening on port", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		fmt.Printf("NEW CONN")
		go func() {
    		if err := handleConnection(conn); err != nil {
        	log.Println("connection error:", err)
    	}
}()

	}
}

func handleConnection(conn net.Conn) error {
	framed := session.NewFramedConn(conn)
	defer framed.Close()

	// fmt.Printf("NEW CONN")

	raw, err := framed.Recv()
	// fmt.Printf("RECEIVED: %s")
	if err != nil {
		// log.Println("Failed to receive initial message from:", framed.RemoteAddr())
		return err
	}

	var base protocol.BaseMessage
	if err := json.Unmarshal(raw, &base); err != nil {
		// log.Println("Failed to parse initial JSON message from:", framed.RemoteAddr())
	}

	switch base.Type {
	case protocol.EKE_1:
		fmt.Printf("EKE1 received")
		parsed, err := protocol.ParseMessage[protocol.EKE1Message](raw); if err != nil {
			// log.Println("Failed to parse EKE1 message")
			return err
		}

		w := "JacobLiam"

		secureSession, err := auth.RunServerSideDhEKE(framed, parsed, w, "Liam-PC"); if err != nil {
			return err
		}
		go RunSecureApp(secureSession)
	case protocol.STS_1:
		fmt.Printf("STS Received")
		// parsed, err := protocol.ParseMessage[protocol.STS1Message](raw); if err != nil {
		// 	// log.Println("Failed to parse STS1 message")
		// 	return
		// }

		// secureSession = auth.R

	}
	return nil
}

func RunSecureApp(session *session.SecureSession) {
	session.PrintPrivateKeyLmao()
}