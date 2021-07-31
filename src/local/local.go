package local

import (
	"bytes"
	"encoding/binary"
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
	cipher   encrypt.Cipher
	listener *net.TCPListener
	remote   *net.TCPConn
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
	unix.SetsockoptInt(int(f.Fd()), unix.SOL_SOCKET,
		unix.SO_REUSEADDR, 1)

	raddr, err := net.ResolveTCPAddr("tcp", remote)
	if err != nil {
		return nil, errors.New("resolve remote error")
	}
	remoteConn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return nil, errors.New("dial remote server error")
	}
	remoteConn.SetNoDelay(true)

	return &Local{
		cipher:   cipher,
		listener: listener,
		remote:   remoteConn,
	}, nil
}

func (l *Local) CloseListener() error {
	return l.listener.Close()
}

func (l *Local) CloseRemote() error {
	return l.remote.Close()
}

func (l *Local) AcceptTCP() (*net.TCPConn, error) {
	return l.listener.AcceptTCP()
}

func (l *Local) Serve() {
	defer l.CloseListener()
	defer l.CloseRemote()
	for {
		conn, err := l.AcceptTCP() // conn from local client supporting socks5
		if err != nil {
			log.Printf("accept() error: %s", err)
			continue
		}
		go l.handleConn(conn)
	}
}

func (l *Local) handleConn(conn *net.TCPConn) {
	defer conn.Close()

	// parse socks5 traffic from client
	s, err := socks.GetRemote(conn)
	if err != nil {
		log.Println(err)
		return
	}

	// encode parse result to binary
	var buffer bytes.Buffer
	if err = binary.Write(&buffer, binary.BigEndian, s); err != nil {
		log.Println(err)
		return
	}

	_, err = l.cipher.EncryptCopy(l.remote, &buffer)
	log.Println("dial", s.String())
	if err != nil {
		socks.ResponseConn(conn, 0x04)
		log.Println("send encode data error")
		return
	}

	reply := make([]byte, 1)
	l.remote.Read(reply)
	err = socks.ResponseConn(conn, reply[0])
	if err != nil {
		log.Println(err)
		return
	}
	if reply[0] != 0x00 {
		log.Printf("bad connection, erron: %d\n", reply[0])
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		l.cipher.DecryptCopy(conn, l.remote)
		wg.Done()
	}()
	go func() {
		l.cipher.EncryptCopy(l.remote, conn)
	}()
	wg.Wait()
}
