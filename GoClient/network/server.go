package network

import (
	"fmt"
	"log"
	"net"
	"time"
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

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer func() {
		log.Println("Client disconnected:", conn.RemoteAddr())
		conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		text := string(buf[:n])
		log.Printf("Received from %s: %s\n", conn.RemoteAddr(), text)
		// Echo 
		conn.Write([]byte("Echo: " + text))
	}
}

func SendMessage(ip string, port int, message string) {
	// maybe should be 	addr := fmt.Sprintf("%s:%d", ip, port)
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		log.Println("Failed to connect to:", ip, ":", err)
		return
	}
	defer conn.Close()
	conn.Write([]byte(message))
}