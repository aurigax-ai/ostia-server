package testkit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type FakeGateway struct {
	Addr    string
	Token   string
	Peers   chan string
	Confirm func(peer string)
	ln      net.Listener
	cert    tls.Certificate
}

func StartGateway(t testing.TB, cert Gateway) *FakeGateway {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &FakeGateway{Addr: ln.Addr().String(), Token: EncodeB64(RandomBytes(16)), Peers: make(chan string, 64), ln: ln, cert: cert.Cert}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go g.serve(conn)
		}
	}()
	return g
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (g *FakeGateway) serve(raw net.Conn) {
	defer raw.Close()
	reader := bufio.NewReader(raw)
	header, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(header, "PROXY ") {
		return
	}
	fields := strings.Fields(header)
	if len(fields) != 6 {
		return
	}
	peer := net.JoinHostPort(fields[2], fields[4])
	select {
	case g.Peers <- peer:
	default:
	}
	conn := tls.Server(bufferedConn{Conn: raw, reader: reader}, &tls.Config{Certificates: []tls.Certificate{g.cert}, MinVersion: tls.VersionTLS12})
	defer conn.Close()
	lines := bufio.NewScanner(conn)
	if !lines.Scan() || lines.Text() != "hello "+g.Token {
		_, _ = fmt.Fprintln(conn, "denied")
		return
	}
	if g.Confirm != nil {
		g.Confirm(peer)
	}
	if _, err := fmt.Fprintln(conn, "welcome"); err != nil {
		return
	}
	for lines.Scan() {
		if _, err := fmt.Fprintf(conn, "gateway saw %s from %s\n", lines.Text(), peer); err != nil {
			return
		}
	}
}

type RelayDesktop struct {
	API     *API
	Gateway *FakeGateway
	Label   string
	Host    string
	Port    int

	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.Mutex
	Pings   int
	control *websocket.Conn
	streams map[string]string
}

func (d *RelayDesktop) Prepare(t testing.TB) {
	t.Helper()
	m := d.API.Must(t, http.StatusOK, "POST", "/v1/relay/label", nil).Map(t)
	d.Label, d.Host, d.Port = m["label"].(string), m["host"].(string), int(m["port"].(float64))
}

func (d *RelayDesktop) dial(ctx context.Context, path string) (*websocket.Conn, error) {
	url := "wss://" + d.API.Net.APIHost + path
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPClient: d.API.Client,
		HTTPHeader: http.Header{"Authorization": {"Bearer " + d.API.Token}},
	})
	return c, err
}

func (d *RelayDesktop) Listen(t testing.TB) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	control, err := d.dial(ctx, "/v1/relay/listen")
	if err != nil {
		cancel()
		t.Fatalf("relay listen: %v", err)
	}
	d.mu.Lock()
	d.control = control
	d.streams = map[string]string{}
	d.mu.Unlock()
	d.Gateway.Confirm = d.confirmPeer
	d.wg.Go(func() {
		defer control.CloseNow()
		for {
			_, data, err := control.Read(ctx)
			if err != nil {
				return
			}
			var msg struct {
				Type   string `json:"t"`
				Stream string `json:"stream"`
				Peer   string `json:"peer"`
				Family int    `json:"family"`
			}
			if json.Unmarshal(data, &msg) != nil {
				continue
			}
			switch msg.Type {
			case "ping":
				d.mu.Lock()
				d.Pings++
				d.mu.Unlock()
				_ = control.Write(ctx, websocket.MessageText, []byte(`{"t":"pong"}`))
			case "incoming":
				d.mu.Lock()
				d.streams[msg.Peer] = msg.Stream
				d.mu.Unlock()
				d.wg.Go(func() { d.accept(ctx, msg.Stream, msg.Peer, msg.Family) })
			}
		}
	})
	t.Cleanup(d.Stop)
}

func (d *RelayDesktop) confirmPeer(peer string) {
	d.mu.Lock()
	stream, control := d.streams[peer], d.control
	d.mu.Unlock()
	if stream == "" || control == nil {
		return
	}
	raw, _ := json.Marshal(map[string]string{"t": "confirm", "stream": stream})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = control.Write(ctx, websocket.MessageText, raw)
}

func (d *RelayDesktop) accept(ctx context.Context, stream, peer string, family int) {
	ws, err := d.dial(ctx, "/v1/relay/accept/"+stream)
	if err != nil {
		return
	}
	ws.SetReadLimit(-1)
	remote := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	defer remote.Close()
	local, err := net.Dial("tcp", d.Gateway.Addr)
	if err != nil {
		return
	}
	defer local.Close()
	host, port, _ := net.SplitHostPort(peer)
	proto := "TCP4"
	if family == 6 {
		proto = "TCP6"
	}
	if _, err := fmt.Fprintf(local, "PROXY %s %s 127.0.0.1 %s %s\r\n", proto, host, port, port); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(local, remote); done <- struct{}{} }()
	go func() { _, _ = io.Copy(remote, local); done <- struct{}{} }()
	<-done
}

func (d *RelayDesktop) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
	d.wg.Wait()
}

func (d *RelayDesktop) PingCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Pings
}

var ErrPinMismatch = errors.New("certificate does not match the pinned fingerprint")

func DialPhone(ctx context.Context, n Net, host, pin string) (*tls.Conn, error) {
	raw, err := n.Dial(ctx)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(certs [][]byte, _ [][]*x509.Certificate) error {
			if len(certs) == 0 {
				return ErrPinMismatch
			}
			sum := sha256.Sum256(certs[0])
			if hex.EncodeToString(sum[:]) != pin {
				return ErrPinMismatch
			}
			return nil
		},
	})
	hs, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(hs); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

func Converse(conn net.Conn, line string) (string, error) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(conn, line); err != nil {
		return "", err
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSpace(reply), err
}

var ErrGatewayDenied = errors.New("gateway denied the hello")

func Hello(conn net.Conn, token string) error {
	reply, err := Converse(conn, "hello "+token)
	if err != nil {
		return err
	}
	if reply != "welcome" {
		return ErrGatewayDenied
	}
	return nil
}

func DialAuthed(ctx context.Context, n Net, host, pin, token string) (*tls.Conn, error) {
	conn, err := DialPhone(ctx, n, host, pin)
	if err != nil {
		return nil, err
	}
	if err := Hello(conn, token); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
