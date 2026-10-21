package e2e

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func clientHelloBytes(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	go func() {
		conn := tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = conn.HandshakeContext(ctx)
		_ = client.Close()
	}()
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, int(header[3])<<8|int(header[4]))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	return append(header, body...)
}
