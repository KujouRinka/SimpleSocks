package server

import (
	"encrypt"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"proto/socks"
	"sync"
)

type Server struct {
	cipher   encrypt.Cipher
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
	f, _ := listener.File()

	// disable time-wait if possible
	unix.SetsockoptInt(int(f.Fd()), unix.SOL_SOCKET,
		unix.SO_REUSEADDR, 1)

	return &Server{
		cipher:   cipher,
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

	conn.SetNoDelay(true)

	reqBuf := make([]byte, 261)
	n, err := conn.Read(reqBuf)
	if err != nil {
		log.Println("getting sock5 request error")
		return
	}
	reqBuf = reqBuf[:n]
	s.cipher.Decrypt(reqBuf)
	socksReq, err := socks.NewReq(reqBuf)
	if err != nil {
		log.Println("parse socks5 req pack error:", err)
		return
	}

	// dial dst addr
	var cmd string
	switch socksReq.Cmd() {
	case 0x01:
		cmd = "tcp"
	case 0x02:
	case 0x03:
		cmd = "udp"
	}
	remote, err := net.Dial(cmd, socksReq.AdrPort())

	// disable nagle algorithm for tcp conn
	if t, ok := remote.(*net.TCPConn); ok {
		// log.Println("disabled nagle")
		t.SetNoDelay(true)
	}

	// write socks5 status
	if err != nil {
		log.Printf("dial %s error\n", socksReq.AdrPort())
		socks.WriteResp(conn, 0x04, s.cipher)
		return
	}
	defer remote.Close()
	err = socks.WriteResp(conn, 0x00, s.cipher)
	if err != nil {
		log.Println("write sock5 status error")
		return
	}

	if remote == nil {
		log.Println("dial remote error, got nil")
		return
	}
	log.Printf("connecting to %s(%s) successfully\n",
		socksReq.AdrPort(), remote.RemoteAddr())

	// handle connection
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
