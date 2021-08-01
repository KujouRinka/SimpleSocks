package proto

import (
	"encoding/binary"
	"net"
	"strconv"
)

type Port []byte

type Adr struct {
	AdrType byte
	Adr     []byte
}

type AdrPort struct {
	Adr
	Port
}

func NewPort(b []byte) Port {
	return Port(b)
}

func (p Port) Uint16() uint16 {
	return binary.BigEndian.Uint16(p)
}

func (p Port) String() string {
	return strconv.FormatUint(uint64(p.Uint16()), 10)
}

func NewAdr(adrType byte, adr []byte) *Adr {
	return &Adr{
		AdrType: adrType,
		Adr:     adr,
	}
}

func (a Adr) String() string {
	var parseResult string

	switch a.AdrType {
	case 0x01, 0x04:
		parseResult = (net.IP)(a.Adr).String()
	case 0x03:
		parseResult = string(a.Adr)
	}
	return parseResult
}

func NewAdrPort(adrType byte, adr []byte, port []byte) *AdrPort {
	return &AdrPort{
		Adr: Adr{
			AdrType: adrType,
			Adr:     adr,
		},
		Port: port,
	}
}

func (a *AdrPort) String() string {
	return a.Adr.String() + ":" + a.Port.String()
}
