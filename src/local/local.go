package local

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

type Local struct {
	cipher     encrypt.Cipher
	listener   *net.TCPListener
	serverAddr *net.TCPAddr
}

func New(cipher encrypt.Cipher, port string, remote string) (*Local, error) {
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

	raddr, err := net.ResolveTCPAddr("tcp", remote)
	if err != nil {
		return nil, errors.New("resolve remote error")
	}

	return &Local{
		cipher:     cipher,
		listener:   listener,
		serverAddr: raddr,
	}, nil
}

func (l *Local) CloseListener() error {
	return l.listener.Close()
}

func (l *Local) AcceptTCP() (*net.TCPConn, error) {
	return l.listener.AcceptTCP()
}

func (l *Local) DialServer() (*net.TCPConn, error) {

	remoteConn, err := net.DialTCP("tcp", nil, l.serverAddr)
	if err != nil {
		return nil, errors.New("dial remote server error")
	}

	// disable nagle algorithm
	remoteConn.SetNoDelay(true)
	return remoteConn, nil
}

func (l *Local) Serve() {
	defer l.CloseListener()
	for {
		conn, err := l.AcceptTCP() // conn from local client supporting socks5
		if err != nil {
			log.Printf("accept() error: %s", err)
			continue
		}
		conn.SetLinger(0)
		go l.handleConn(conn)
	}
}

func (l *Local) handleConn(conn *net.TCPConn) {
	defer conn.Close()

	// greeting socks5
	err := socks.HandleGreeting(conn)
	if err != nil {
		log.Println("handle greeting error:", err)
		return
	}

	// handle request from client
	req, err := socks.ReadReq(conn)
	if err != nil {
		log.Println("read req error:", err)
		return
	}
	remote, err := l.DialServer()
	if err != nil {
		log.Println("dial server error")
		conn.Write([]byte{
			0x05, 0x01, 0x00, 0x01, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00,
		})
		return
	}
	defer remote.Close()
	remote.SetNoDelay(true)
	remote.SetLinger(0)

	remoteAddr := (socks.Req)(req).AdrPort()
	l.cipher.Encrypt(req)
	_, err = remote.Write(req)
	if err != nil {
		log.Println("write req error:", err)
		return
	}

	resp := make([]byte, 10)
	_, err = remote.Read(resp)
	if err != nil {
		log.Println("read response error:", err)
		return
	}
	l.cipher.Decrypt(resp)
	conn.Write(resp)

	if resp[1] != 0x00 {
		log.Println("socks5 connection error")
		return
	}
	log.Printf("dial to %s successfully\n", remoteAddr)

	// handle connection
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		l.cipher.DecryptCopy(conn, remote)
		wg.Done()
	}()
	go func() {
		l.cipher.EncryptCopy(remote, conn)
	}()
	wg.Wait()
}
