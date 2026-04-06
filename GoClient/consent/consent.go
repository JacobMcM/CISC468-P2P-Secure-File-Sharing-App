/*
This package exists to create a communication protocol between tcp_client and tcp_server
When the server receives a consent request from a peer, it passes it to the client's REPL via Request,
and waits for client to write a response to the channel
*/

package consent

type ConsentRequest struct {
	Message  string
	Response chan bool
}

var Ch = make(chan ConsentRequest)

func Request(message string) bool {
	req := ConsentRequest{
		Message:  message,
		Response: make(chan bool, 1),
	}
	Ch <- req
	return <-req.Response
}