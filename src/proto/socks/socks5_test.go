package socks

import (
	"net"
	"testing"
)

func TestAddrParse(t *testing.T) {
	pack1 := Req{
		0x05, 0x01, 0x00, 0x01, 0x7f,
		0x00, 0x00, 0x01, 0x09, 0x1d,
	} // 127.0.0.1:2333
	if pack1.AdrLen() == net.IPv4len {
		t.Log("sock5 parse IPv4 len successfully")
	} else {
		t.Errorf("sock5 parse IPv4 len error, expect \"%d\" but given \"%d\"",
			net.IPv4len, pack1.AdrLen())
	}
	if pack1.AdrPort() == "127.0.0.1:2333" {
		t.Log("socks5 parse IPv4 port successfully")
	} else {
		t.Errorf("socks5 parse IPv4 port error, expect \"127.0.0.1:2333\" but given \"%s\"",
			pack1.AdrPort())
	}

	pack2 := Req{
		0x05, 0x01, 0x00, 0x03,
		0x01, byte('g'), 0x00, 0x50,
	} //g:80
	if pack2.AdrLen() == 1 {
		t.Log("sock5 parse domain len successfully")
	} else {
		t.Errorf("sock5 parse domain len error, expect \"1\" but given \"%d\"",
			pack2.AdrLen())
	}
	if pack2.AdrPort() == "g:80" {
		t.Log("socks5 parse domain successfully")
	} else {
		t.Errorf("socks5 parse domain error, expect \"g:80\" but given \"%s\"",
			pack2.AdrPort())
	}
}
