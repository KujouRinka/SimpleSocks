package server

import (
	"bytes"
	"encoding/binary"
	"encrypt"
	"errors"
	"fmt"
	"log"
	"net"
	"proto/socks"
	"sync"
)

type Server struct {
	cipher encrypt.Cipher
	listener *net.TCPListener
}

func New(cipher encrypt.Cipher, port string) (*Server, error) {
	laddr, err := net.ResolveTCPAddr("tcp", ":"+port)
	if err != nil {
		return nil, errors.New("resolve local port error")
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return nil, errors.New(
			fmt.Sprintf("listen port %s error", port))
	}

	return &Server{
		cipher: cipher,
		listener: listener,
	}, nil
}

func (s *Server) CloseListener() error {
	return s.listener.Close()
}

func (s *Server) AcceptTCP() (*net.TCPConn, error) {
	return s.listener.AcceptTCP()
}

func (s *Server) Serve() {
	defer s.CloseListener()
	for {
		conn, err := s.AcceptTCP()
		if err != nil {
			log.Println(err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn *net.TCPConn) {
	defer conn.Close()

	//receive raw request and decrypt into struct
	var buffer bytes.Buffer
	_, err := s.cipher.DecryptCopy(&buffer, conn)
	if err != nil {
		log.Println("read raw data error")
		return
	}
	sockData := socks.Socks{}
	binary.Read(&buffer, binary.BigEndian, &sockData)

	// reply local
	var cmd string
	var reply []byte
	switch sockData.Cmd {
	case 0x01:
		cmd = "tcp"
		reply = []byte{0x00}
	case 0x02:
		reply = []byte{0x07}
	case 0x03:
		cmd = "udp"
		reply = []byte{0x00}
	}
	s.cipher.Encrypt(reply)
	conn.Write(reply)

	// dial dst addr
	remote, err := net.Dial(cmd, sockData.String())
	if err != nil {
		log.Printf("dial %s error\n", remote.RemoteAddr())
		return
	}
	defer remote.Close()

	if remote == nil {
		log.Println("dial remote error, got nil")
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		s.cipher.EncryptCopy(conn, remote)
		wg.Done()
	}()
	go func() {
		s.cipher.DecryptCopy(remote, conn)
		wg.Done()
	}()
	wg.Wait()
}
