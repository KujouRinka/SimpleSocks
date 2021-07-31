package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

type Socks struct {
	Ver     byte
	Cmd     byte
	AdrType byte
	Adr     []byte
	Port    []byte
}

func (s *Socks) String() string {
	var dstStr string
	var portStr string
	switch s.AdrType {
	case 0x01:
		dstStr = (net.IP)(s.Adr).String()
	case 0x03:
		dstStr = string(s.Adr)
	case 0x04:
		dstStr = (net.IP)(s.Adr).String()
	}
	port := binary.BigEndian.Uint16(s.Port)
	portStr = strconv.FormatUint(uint64(port), 10)
	return dstStr + ":" + portStr
}

func GetRemote(conn net.Conn) (*Socks, error) {

	// handling client greeting
	buf := make([]byte, 257)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, errors.New("socks5 greeting error")
	}
	buf = buf[:n]
	if buf[0] != 0x05 {
		return nil, errors.New(
			fmt.Sprintf("unsupported proto version: %d", buf[0]))
	}
	// nMethods := uint8(buf[1])
	// methods := buf[2 : 2+nMethods]
	// Suppose client must support 0x00

	_, err = conn.Write([]byte{0x05, 0x00})
	if err != nil {
		return nil, errors.New("response greeting error")
	}
	ver := byte(0x05)

	// handling client connection request
	reqBuf := make([]byte, 261)
	n, err = conn.Read(reqBuf)
	if err != nil {
		return nil, errors.New("getting sock5 request error")
	}
	reqBuf = reqBuf[:n]

	// parse cmd
	cmd := reqBuf[1]
	switch cmd {
	case 0x01:
	case 0x02:
	case 0x03:
		// more thing need doing
		// connMethod := "udp"
	default:
	}

	// parse address type
	var dstAddr []byte
	var dstLen uint8
	adrType := reqBuf[3]
	switch adrType {
	case 0x01:
		dstLen = net.IPv4len
		dstAddr = reqBuf[4 : 4+net.IPv4len]
	case 0x03:
		dstLen = dstAddr[4] + 1
		dstAddr = reqBuf[5 : 5+dstAddr[4]]
	case 0x04:
		dstLen = net.IPv6len
		dstAddr = reqBuf[4 : 4+net.IPv6len]
	}

	port := reqBuf[4+dstLen:]

	return &Socks{
		Ver:     ver,
		Cmd:     cmd,
		AdrType: adrType,
		Adr:     dstAddr,
		Port:    port,
	}, nil
}

func ResponseConn(conn net.Conn, status byte) error {
	response := []byte{
		0x05, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00,
	}
	response[1] = status
	_, err := conn.Write(response)
	if err != nil {
		return errors.New("response proto client error")
	}
	return nil
}
