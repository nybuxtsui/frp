package core

import (
	"errors"
	"net"
)

func NewConn(conn net.Conn, key string) (net.Conn, error) {
	cipher, err := PickCipher("CHACHA20-IETF-POLY1305", nil, key)
	if err != nil {
		return nil, errors.New("invalid cipher")
	}
	return &Conn{
		cipher.StreamConn(conn),
		conn,
	}, nil

}

type Conn struct {
	aeadConn net.Conn
	net.Conn
}

func (c *Conn) Read(p []byte) (n int, err error) {
	return c.aeadConn.Read(p)
}

func (c *Conn) Write(p []byte) (n int, err error) {
	return c.aeadConn.Write(p)
}

func (c *Conn) Close() error {
	c.Conn.Close()
	return c.aeadConn.Close()
}
func (c *Conn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// RemoteAddr returns the remote network address, if known.
func (c *Conn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}
