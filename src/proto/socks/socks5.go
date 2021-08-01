package socks

import (
	"bytes"
	"encrypt"
	"errors"
	"fmt"
	"net"
	"proto"
)

type Req []byte

func NewReq(b []byte) (Req, error) {
	bSize := len(b)
	if bSize < 5 {
		return nil, errors.New("invalid socks5 pack")
	}
	var expectSz int
	switch b[3] {
	case 0x01:
		expectSz = net.IPv4len + 6
	case 0x03:
		expectSz = int(b[4]) + 7
	case 0x04:
		expectSz = net.IPv6len + 6
	}
	if bSize != expectSz {
		return nil, errors.New("invalid socks5 pack")
	}
	return b, nil
}

func (r Req) Ver() byte {
	return r[0]
}

func (r Req) Cmd() byte {
	return r[1]
}

func (r Req) AdrType() byte {
	return r[3]
}

func (r Req) DstAdr() []byte {
	switch r.AdrType() {
	case 0x01:
		return r[4 : 4+r.AdrLen()]
	case 0x03:
		return r[4 : 5+r.AdrLen()]
	case 0x04:
		return r[4 : 4+r.AdrLen()]
	default:
		return nil
	}
}

func (r Req) Port() []byte {
	return r[len(r)-2:]
}

func (r Req) AdrLen() uint16 {
	switch r.AdrType() {
	case 0x01:
		return net.IPv4len
	case 0x03:
		return uint16(r[4])
	case 0x04:
		return net.IPv6len
	default:
		return 0
	}
}

func (r Req) Adr() []byte {
	switch r.AdrType() {
	case 0x01:
		return r[4 : 4+r.AdrLen()]
	case 0x03:
		return r[5 : 5+r.AdrLen()]
	case 0x04:
		return r[4 : 4+r.AdrLen()]
	default:
		return nil
	}
}

func (r Req) AdrPort() string {
	return proto.NewAdrPort(
		r.AdrType(), r.Adr(), r.Port()).String()
}

func HandleGreeting(conn *net.TCPConn) error {
	buf := make([]byte, 257)
	n, err := conn.Read(buf)
	if err != nil {
		return errors.New("socks5 greeting error")
	}
	buf = buf[:n]
	if buf[0] != 0x05 {
		return errors.New(
			fmt.Sprintf("unsupported proto version: %d", buf[0]))
	}
	// nMethods := uint8(buf[1])
	// methods := buf[2 : 2+nMethods]
	// Suppose client must support 0x00

	_, err = conn.Write([]byte{0x05, 0x00})
	if err != nil {
		return errors.New("response greeting error")
	}
	return nil
}

func ReadReq(conn *net.TCPConn) ([]byte, error) {
	// handling client connection request
	reqBuf := make([]byte, 262)
	n, err := conn.Read(reqBuf)
	if err != nil {
		return nil, errors.New("getting sock5 request error")
	}
	return reqBuf[:n], nil
}

func WriteResp(conn net.Conn, status byte, cipher encrypt.Cipher) error {
	resp := []byte{
		0x05, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00,
	}
	resp[1] = status
	buf := bytes.NewBuffer(resp)
	cipher.EncryptCopy(conn, buf)

	return nil
}
