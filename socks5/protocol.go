package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
)

// VER indicate protocol version
type VER = uint8

const (
	V5 VER = 0x05
)

// METHOD indacate authentication method
type METHOD = uint8

const (
	noAuth              METHOD = 0x00
	authGSSAPI          METHOD = 0x01
	authPassword        METHOD = 0x02
	authNoMatchedMethod METHOD = 0xff
)

// CMD indicate client request type
type CMD = uint8

const (
	CONNECT      CMD = 0x01
	BIND         CMD = 0x02
	UDPASSOCIATE CMD = 0x03
)

// REP indicate server reply type
type REP = uint8

const (
	Succeeded              REP = 0x00
	GeneralSOCKSServerFail REP = 0x01
	ConnNotAllow           REP = 0x02
	NetworkUnreachable     REP = 0x03
	HostUnreachable        REP = 0x04
	ConnectionRefused      REP = 0x05
	TTLExpired             REP = 0x06
	CMDNotSupported        REP = 0x07
	ATYPENotSupported      REP = 0x08
)

// ATYP indicate remote server address type
type ATYP = uint8

const (
	IPV4       ATYP = 0x01
	DOMAINNAME ATYP = 0x03
	IPV6       ATYP = 0x04
)

// Request
//Requests Once the method-dependent subnegotiation has completed, the client
//sends the request details.
//The SOCKS request is formed as follows:
//
//		+----+-----+-------+------+----------+----------+
//		|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//		+----+-----+-------+------+----------+----------+
//		| 1  |  1  | X'00' |  1   | Variable |    2     |
//		+----+-----+-------+------+----------+----------+
type Request struct {
	VER
	CMD uint8
	RSV uint8
	ATYP
	DesTAddr net.IP
	DestPort uint16
}

//NewRequest returns a new Request given a Version param
func NewRequest(ver VER) *Request {
	return &Request{
		VER: ver,
		RSV: 0x00,
	}
}

//SerializeRequest serialize request to []byte
func SerializeRequest(request Request) ([]byte, error) {
	var content bytes.Buffer
	var err error
	err = content.WriteByte(request.VER)
	if err != nil {
		return nil, err
	}
	err = content.WriteByte(request.CMD)
	if err != nil {
		return nil, err
	}
	err = content.WriteByte(request.RSV)
	if err != nil {
		return nil, err
	}
	err = content.WriteByte(request.ATYP)
	if err != nil {
		return nil, err
	}
	_, err = content.Write(request.DesTAddr)
	if err != nil {
		return nil, err
	}

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, request.DestPort)
	_, err = content.Write(port)
	if err != nil {
		return nil, err
	}
	return content.Bytes(), nil
}

// ErrReqLength is returned by DeserializeRequest function when content had
// incorrect length.
var ErrReqLength = errors.New("request length is incorrect")

// DeserializeRequest deserialize content to a request
func DeserializeRequest(content []byte) (*Request, error) {
	contentLen := len(content)
	if content == nil {
		return nil, errors.New("nil buffer")
	}

	if contentLen < 4 {
		return nil, errors.New("request is too short")
	}

	req := new(Request)
	req.VER = content[0]
	req.CMD = content[1]
	req.RSV = content[2]
	req.ATYP = content[3]

	switch req.ATYP {
	case IPV4:
		if contentLen != 6+net.IPv4len {
			return nil, ErrReqLength
		}
		req.DesTAddr = content[4:8]
		req.DestPort = binary.BigEndian.Uint16(content[8:])
	case IPV6:
		if contentLen != 6+net.IPv6len {
			return nil, ErrReqLength
		}
		req.DesTAddr = content[4:20]
		req.DestPort = binary.BigEndian.Uint16(content[20:])
	case DOMAINNAME:
		addressLen := int(content[4]) + 6 + 1
		if contentLen != addressLen {
			return nil, ErrReqLength
		}
		ipAddr, err := net.ResolveIPAddr("ip", string(content[4:addressLen]))
		if err != nil {
			return nil, err
		}
		req.DesTAddr = ipAddr.IP
		req.DestPort = binary.BigEndian.Uint16(content[addressLen:])
	default:
		return nil, errors.New("unknown address type")
	}
	return req, nil
}

// Reply
//The SOCKS request information is sent by the client as soon as it has
//established a connection to the SOCKS server, and completed the
//authentication negotiations.  The server evaluates the request, and
//returns a reply formed as follows:
//
//		+----+-----+-------+------+----------+----------+
//		|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//		+----+-----+-------+------+----------+----------+
//		| 1  |  1  | X'00' |  1   | Variable |    2     |
//		+----+-----+-------+------+----------+----------+
type Reply struct {
	VER
	REP
	RSV uint8
	ATYP
	BNDAddr net.IP
	BNDPort uint16
}

// NewReply returns a new Reply given a Version param
func NewReply(ver VER) *Reply {
	return &Reply{
		VER: ver,
		RSV: 0x00,
	}
}

// SerializeReply
func SerializeReply(reply Reply) ([]byte, error) {
	return nil, nil
}

// DeserializeReply
func DeserializeReply(content []byte) (*Reply, error) {
	return nil, nil
}
