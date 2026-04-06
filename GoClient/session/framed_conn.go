/*
framed_conn.go wraps a TCP connection object with length prefixed Send/Receive methods
*/

package session

import (
	"encoding/binary"
	"io"
	"net"
)

type FramedConn struct {
	conn     net.Conn
}

func NewFramedConn(conn net.Conn) *FramedConn {
	return &FramedConn{conn: conn}
}

func (c *FramedConn) Send(msg []byte) error {
    length := uint32(len(msg))
    if err := binary.Write(c.conn, binary.BigEndian, length); err != nil {
        return err
    }
    _, err := c.conn.Write(msg)
    return err
}

func (c *FramedConn) Recv() ([]byte, error) {
    var length uint32
    if err := binary.Read(c.conn, binary.BigEndian, &length); err != nil {
        return nil, err
    }
    buf := make([]byte, length)
    _, err := io.ReadFull(c.conn, buf)
    return buf, err
}

func (c *FramedConn) Close() error {
	return c.conn.Close()
}

func (c *FramedConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}