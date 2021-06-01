package socks5

import (
	"log"
	"net"
)

// Server is a socks5 server
type Server struct {
	Addr string
	ln   net.Listener
}

// Listen on server's address & port
func (s *Server) Listen() error {
	var (
		err error
	)

	s.ln, err = net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) Accept() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go s.HandleClient(conn)
	}
}

func (s *Server) HandleClient(client net.Conn) error {
	buf := make([]byte, 255)

	//1. handshake
	n, err := client.Read(buf)
	if err != nil {
		return err
	}

	//2. handle client request
	request, err := DeserializeRequest(buf[:n])
	if err != nil {
		return err
	}

	_ = request
	return nil
}

func HandShake() {

}

func HandShake4() {
	panic("not implement")
}

func HandShake5() {

}
