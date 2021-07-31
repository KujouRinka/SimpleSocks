package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

type Socks struct {
	Ver        byte
	Cmd        byte
	AdrType    byte
	RemoteAddr string
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
			fmt.Sprintf("unsupported socks version: %d", buf[0]))
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
	var dstStr string
	adrType := reqBuf[3]
	switch adrType {
	case 0x01:
		dstLen = net.IPv4len
		dstAddr = reqBuf[4 : 4+net.IPv4len]
		dstStr = (net.IP)(dstAddr).String()
	case 0x03:
		dstLen = dstAddr[4] + 1
		dstAddr = reqBuf[5 : 5+dstAddr[4]]
		dstStr = string(dstAddr)
	case 0x04:
		dstLen = net.IPv6len
		dstAddr = reqBuf[4 : 4+net.IPv6len]
		dstStr = (net.IP)(dstAddr).String()
	}

	port := binary.BigEndian.Uint16(reqBuf[4+dstLen:])
	portStr := strconv.FormatUint(uint64(port), 10)
	remoteAddrStr := dstStr + ":" + portStr

	return &Socks{
		Ver:        ver,
		Cmd:        cmd,
		AdrType:    adrType,
		RemoteAddr: remoteAddrStr,
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
		return errors.New("response socks client error")
	}
	return nil
}
