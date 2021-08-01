package proto

import "testing"

func TestIPParse(t *testing.T) {
	adr := NewAdr(0x01, []byte{0x7f, 0x00, 0x00, 0x01})
	if adr.String() != "127.0.0.1" {
		t.Errorf("parse IPv4 error, expect \"127.0.0.1\" but given \"%s\"",
			adr.String())
	} else {
		t.Log("parse IPv4 successfully")
	}
}

func TestDomainParse(t *testing.T) {
	adr := NewAdr(0x03, []byte("google.com"))
	if adr.String() != "google.com" {
		t.Errorf("parse domain error, expect \"google.com\" but given \"%s\"",
			adr.String())
	} else {
		t.Log("parse domain successfully")
	}
}

func TestPortParse(t *testing.T) {
	p1 := Port{0x00, 0x50} // 80
	if p1.String() != "80" {
		t.Errorf("pasrse port error, expect \"80\" but given \"%s\"",
			p1.String())
	} else {
		t.Log("parse port successfully")
	}

	p2 := Port{0x5b, 0x25} // 23333
	if p2.String() != "23333" {
		t.Errorf("parse port error, expect \"23333\" but given \"%s\"",
			p1.String())
	} else {
		t.Log("parse port successfully")
	}
}
