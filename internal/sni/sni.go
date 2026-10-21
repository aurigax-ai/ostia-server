package sni

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

const (
	recordTypeHandshake  = 0x16
	handshakeClientHello = 0x01
	extensionServerName  = 0x0000
	nameTypeHostName     = 0x00
	maxRecordBytes       = 16384 + 256
	maxHelloBytes        = 64 << 10
	recordHeaderBytes    = 5
	handshakeHeaderBytes = 4
)

var (
	ErrNotTLS         = errors.New("not a TLS handshake")
	ErrNotClientHello = errors.New("first handshake message is not a ClientHello")
	ErrMalformed      = errors.New("malformed ClientHello")
)

func Peek(r io.Reader) (serverName string, consumed []byte, err error) {
	var raw bytes.Buffer
	var handshake []byte
	for {
		header := make([]byte, recordHeaderBytes)
		if _, err := io.ReadFull(r, header); err != nil {
			return "", raw.Bytes(), err
		}
		raw.Write(header)
		if header[0] != recordTypeHandshake || header[1] != 3 {
			return "", raw.Bytes(), ErrNotTLS
		}
		length := int(header[3])<<8 | int(header[4])
		if length == 0 || length > maxRecordBytes {
			return "", raw.Bytes(), ErrNotTLS
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(r, body); err != nil {
			return "", raw.Bytes(), err
		}
		raw.Write(body)
		handshake = append(handshake, body...)
		if len(handshake) < handshakeHeaderBytes {
			continue
		}
		if handshake[0] != handshakeClientHello {
			return "", raw.Bytes(), ErrNotClientHello
		}
		total := handshakeHeaderBytes + (int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3]))
		if total > maxHelloBytes {
			return "", raw.Bytes(), ErrMalformed
		}
		if len(handshake) >= total {
			name, err := parseServerName(handshake[:total])
			return name, raw.Bytes(), err
		}
	}
}

func parseServerName(hello []byte) (string, error) {
	s := cryptobyte.String(hello)
	var body cryptobyte.String
	var msgType uint8
	if !s.ReadUint8(&msgType) || !s.ReadUint24LengthPrefixed(&body) || msgType != handshakeClientHello {
		return "", ErrMalformed
	}
	var version uint16
	var random, sessionID, suites, compression cryptobyte.String
	if !body.ReadUint16(&version) || !body.ReadBytes((*[]byte)(&random), 32) ||
		!body.ReadUint8LengthPrefixed(&sessionID) ||
		!body.ReadUint16LengthPrefixed(&suites) ||
		!body.ReadUint8LengthPrefixed(&compression) {
		return "", ErrMalformed
	}
	if body.Empty() {
		return "", nil
	}
	var extensions cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&extensions) {
		return "", ErrMalformed
	}
	for !extensions.Empty() {
		var kind uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&kind) || !extensions.ReadUint16LengthPrefixed(&data) {
			return "", ErrMalformed
		}
		if kind != extensionServerName {
			continue
		}
		var names cryptobyte.String
		if !data.ReadUint16LengthPrefixed(&names) {
			return "", ErrMalformed
		}
		for !names.Empty() {
			var nameType uint8
			var name cryptobyte.String
			if !names.ReadUint8(&nameType) || !names.ReadUint16LengthPrefixed(&name) {
				return "", ErrMalformed
			}
			if nameType == nameTypeHostName {
				return normalizeName(string(name)), nil
			}
		}
	}
	return "", nil
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

type PrefixConn struct {
	net.Conn
	prefix *bytes.Reader
}

func NewPrefixConn(conn net.Conn, prefix []byte) *PrefixConn {
	return &PrefixConn{Conn: conn, prefix: bytes.NewReader(prefix)}
}

func (c *PrefixConn) Read(p []byte) (int, error) {
	if c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	return c.Conn.Read(p)
}
