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
	NoAuth              METHOD = 0x00
	AuthGSSAPI          METHOD = 0x01
	AuthPassword        METHOD = 0x02
	AuthNoMatchedMethod METHOD = 0xff
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

// SerializeReply serialize reply to []byte
func SerializeReply(reply Reply) ([]byte, error) {
	var content bytes.Buffer
	var err error
	err = content.WriteByte(reply.VER)
	if err != nil {
		return nil, err
	}
	err = content.WriteByte(reply.REP)
	if err != nil {
		return nil, err
	}
	err = content.WriteByte(reply.RSV)
	if err != nil {
		return nil, err
	}
	err = content.WriteByte(reply.ATYP)
	if err != nil {
		return nil, err
	}
	_, err = content.Write(reply.BNDAddr)
	if err != nil {
		return nil, err
	}

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, reply.BNDPort)
	_, err = content.Write(port)
	if err != nil {
		return nil, err
	}
	return content.Bytes(), nil
}

// DeserializeReply deserialize content to a reply
func DeserializeReply(content []byte) (*Reply, error) {
	contentLen := len(content)
	if content == nil {
		return nil, errors.New("nil buffer")
	}

	if contentLen < 4 {
		return nil, errors.New("request is too short")
	}

	reply := new(Reply)
	reply.VER = content[0]
	reply.REP = content[1]
	reply.RSV = content[2]
	reply.ATYP = content[3]

	switch reply.ATYP {
	case IPV4:
		if contentLen != 6+net.IPv4len {
			return nil, ErrReqLength
		}
		reply.BNDAddr = content[4:8]
		reply.BNDPort = binary.BigEndian.Uint16(content[8:])
	case IPV6:
		if contentLen != 6+net.IPv6len {
			return nil, ErrReqLength
		}
		reply.BNDAddr = content[4:20]
		reply.BNDPort = binary.BigEndian.Uint16(content[20:])
	case DOMAINNAME:
		addressLen := int(content[4]) + 6 + 1
		if contentLen != addressLen {
			return nil, ErrReqLength
		}
		ipAddr, err := net.ResolveIPAddr("ip", string(content[4:addressLen]))
		if err != nil {
			return nil, err
		}
		reply.BNDAddr = ipAddr.IP
		reply.BNDPort = binary.BigEndian.Uint16(content[addressLen:])
	default:
		return nil, errors.New("unknown address type")
	}
	return reply, nil
}
