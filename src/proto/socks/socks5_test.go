package socks

import "testing"

func TestAddrParse(t *testing.T) {
	pack1 := Socks{
		Ver:     0,
		Cmd:     0,
		AdrType: 0x01,
		Adr:     []byte{0x7f, 0x00, 0x00, 0x01},	// 127.0.0.1
		Port:    []byte{0x09, 0x1d},	// 2333
	}
	if pack1.String() == "127.0.0.1:2333" {
		t.Log("sock parse IPv4 successfully")
	} else {
		t.Errorf("sock parse IPv4 error, except \"127.0.0.1:1080\" but given \"%s\"",
			pack1.String())
	}
	pack2 := Socks{
		Ver:     0,
		Cmd:     0,
		AdrType: 0x03,
		Adr:     []byte("google.com"),
		Port:    []byte{0x01, 0xbb},	// 443
	}
	if pack2.String() == "google.com:443" {
		t.Log("sock parse domain successfully")
	} else {
		t.Errorf("sock parse domain error, except \"google.com:443\" but given \"%s\"",
			pack2.String())
	}
}
