package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var cfFallbackIPs = []string{
	"104.21.82.196",
	"172.67.162.213",
	"104.16.132.229",
	"172.64.155.209",
}

var dcIPPools = map[int][]string{
	1: {"149.154.167.220", "149.154.175.50", "149.154.175.53", "2001:67c:4e8:f001::e"},
	2: {"149.154.167.220", "149.154.167.51", "149.154.167.91", "149.154.167.92", "2001:67c:4e8:f002::e"},
	3: {"149.154.167.220", "149.154.175.100", "149.154.175.101", "2001:67c:4e8:f003::e"},
	4: {"149.154.167.220", "149.154.167.91", "149.154.167.92", "149.154.164.250", "2001:67c:4e8:f004::e"},
	5: {"149.154.167.220", "91.108.56.100", "91.108.56.130", "2001:b28:f23f:f005::e"},
}

func (s *Server) dialDirectWebSocket(dc int, isMedia bool, fastMode bool) (*websocket.Conn, string, string, error) {
	hosts := []string{fmt.Sprintf("kws%d.web.telegram.org", dc)}
	if isMedia {
		hosts = []string{
			fmt.Sprintf("kws%d-1.web.telegram.org", dc),
			fmt.Sprintf("kws%d.web.telegram.org", dc),
		}
	}

	timeout := 7 * time.Second
	if fastMode {
		timeout = 2500 * time.Millisecond
	}

	var lastErr error
	for _, host := range hosts {
		wsURL := fmt.Sprintf("wss://%s/apiws", host)
		var usedIP string

		dialer := websocket.Dialer{
			Subprotocols:      []string{"binary"},
			HandshakeTimeout:  timeout,
			ReadBufferSize:    64 * 1024,
			WriteBufferSize:   64 * 1024,
			EnableCompression: false,
			NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, ip, err := s.dialTLSRace(ctx, addr, dc, timeout)
				usedIP = ip
				return conn, err
			},
		}

		wsConn, resp, err := dialer.Dial(wsURL, nil)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			return wsConn, host, usedIP, nil
		}
		lastErr = err
	}
	return nil, "", "", lastErr
}

func (s *Server) pumpDirectWebSocket(clientConn net.Conn, wsConn *websocket.Conn, initPacket []byte, info mtprotoInit, host, usedIP string, id int64) {
	defer wsConn.Close()

	s.setStatus(fmt.Sprintf("Напрямую (%s)", usedIP))
	if info.isMedia {
		s.addLog("DIRECT", fmt.Sprintf("#%d Медиа -> %s (%s)", id, host, usedIP))
	} else {
		s.addLog("DIRECT", fmt.Sprintf("#%d Туннель -> %s (%s)", id, host, usedIP))
	}

	splitter := newMTProtoSplitter(info.protoID, info.stream)
	s.runWebSocketBridge(clientConn, wsConn, initPacket, splitter)
}

func (s *Server) bridgeWorkerTCP(clientConn net.Conn, initialData []byte, dstHost string, dstPort int, id int64) {
	s.mu.RLock()
	relay := s.relayHost
	relayKey := s.relayKey
	s.mu.RUnlock()

	if relay == "" {
		return
	}

	cleanRelay := trimRelayHost(relay)

	wsURL := fmt.Sprintf(
		"wss://%s/apiws?dst=%s&port=%d",
		cleanRelay,
		url.QueryEscape(dstHost),
		dstPort,
	)
	if relayKey != "" {
		wsURL += "&key=" + url.QueryEscape(relayKey)
	}

	var usedIP string
	dialer := websocket.Dialer{
		HandshakeTimeout:  7 * time.Second,
		ReadBufferSize:    64 * 1024,
		WriteBufferSize:   64 * 1024,
		EnableCompression: false,
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, ip, err := s.dialRelayTLS(ctx, addr)
			usedIP = ip
			return conn, err
		},
	}

	wsConn, resp, err := dialer.Dial(wsURL, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		s.setStatus("Ошибка Cloudflare")
		s.addLog("ERR", fmt.Sprintf("#%d CF -> %s:%d: %v", id, dstHost, dstPort, err))
		return
	}
	defer wsConn.Close()

	s.setStatus(fmt.Sprintf("Cloudflare (%s)", usedIP))
	s.addLog("CF", fmt.Sprintf("#%d TCP -> %s:%d (через %s)", id, dstHost, dstPort, usedIP))

	s.runWebSocketBridge(clientConn, wsConn, initialData, nil)
}

func trimRelayHost(relay string) string {
	for _, prefix := range []string{"https://", "http://"} {
		if len(relay) >= len(prefix) && relay[:len(prefix)] == prefix {
			relay = relay[len(prefix):]
		}
	}
	for i := 0; i < len(relay); i++ {
		if relay[i] == '/' || relay[i] == '?' {
			return relay[:i]
		}
	}
	return relay
}

func (s *Server) runWebSocketBridge(clientConn net.Conn, wsConn *websocket.Conn, initialData []byte, splitter *mtprotoSplitter) {
	const pongWait = 45 * time.Second
	const pingPeriod = 15 * time.Second

	s.trackConn(wsConn)
	defer s.untrackConn(wsConn)

	_ = wsConn.SetReadDeadline(time.Now().Add(pongWait))
	wsConn.SetPongHandler(func(string) error {
		_ = wsConn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	if len(initialData) > 0 {
		_ = wsConn.SetWriteDeadline(time.Now().Add(8 * time.Second))
		if err := wsConn.WriteMessage(websocket.BinaryMessage, initialData); err != nil {
			return
		}
		_ = wsConn.SetWriteDeadline(time.Time{})
	}

	var writeMu sync.Mutex
	var closeOnce sync.Once
	done := make(chan struct{})

	shutdown := func() {
		closeOnce.Do(func() {
			close(done)
			_ = wsConn.Close()
			_ = clientConn.Close()
		})
	}

	go func() {
		ticker := time.NewTicker(pingPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				writeMu.Lock()
				_ = wsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				err := wsConn.WriteMessage(websocket.PingMessage, nil)
				_ = wsConn.SetWriteDeadline(time.Time{})
				writeMu.Unlock()
				if err != nil {
					shutdown()
					return
				}
			}
		}
	}()

	go func() {
		defer shutdown()
		for {
			msgType, data, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			_ = wsConn.SetReadDeadline(time.Now().Add(pongWait))
			if msgType != websocket.BinaryMessage {
				continue
			}
			if _, err := clientConn.Write(data); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := clientConn.Read(buf)
		if n > 0 {
			var frames [][]byte
			if splitter != nil {
				frames = splitter.Push(buf[:n])
			} else {
				frames = [][]byte{buf[:n]}
			}

			for _, frame := range frames {
				writeMu.Lock()
				_ = wsConn.SetWriteDeadline(time.Now().Add(8 * time.Second))
				wErr := wsConn.WriteMessage(websocket.BinaryMessage, frame)
				_ = wsConn.SetWriteDeadline(time.Time{})
				writeMu.Unlock()
				if wErr != nil {
					shutdown()
					return
				}
			}
		}
		if err != nil {
			break
		}
	}
	shutdown()
}

func (s *Server) dialRelayTLS(ctx context.Context, addr string) (net.Conn, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, "", err
	}

	s.workingIPMu.RLock()
	cachedRelay := s.workingRelayIP
	s.workingIPMu.RUnlock()

	if cachedRelay != "" {
		fastCtx, cancel := context.WithTimeout(ctx, 1800*time.Millisecond)
		// Для Cloudflare Worker всегда проверяем TLS-сертификат (insecure = false)
		conn, err := s.dialSingleTLS(fastCtx, cachedRelay, port, host, false)
		cancel()
		if err == nil {
			return conn, cachedRelay, nil
		}
		s.workingIPMu.Lock()
		if s.workingRelayIP == cachedRelay {
			s.workingRelayIP = ""
		}
		s.workingIPMu.Unlock()
	}

	seen := make(map[string]bool)
	var candidates []string
	add := func(ip string) {
		if ip != "" && ip != cachedRelay && !seen[ip] {
			seen[ip] = true
			candidates = append(candidates, ip)
		}
	}

	dnsCtx, cancelDNS := context.WithTimeout(ctx, 1500*time.Millisecond)
	for _, ip := range s.doh.ResolveAllIPv4(dnsCtx, host) {
		add(ip)
	}
	cancelDNS()

	for _, fb := range cfFallbackIPs {
		add(fb)
	}

	if len(candidates) == 0 {
		return nil, "", errors.New("нет доступных узлов Cloudflare")
	}

	raceCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	type raceResult struct {
		conn net.Conn
		ip   string
		err  error
	}
	resCh := make(chan raceResult, len(candidates))

	for _, candidateIP := range candidates {
		go func(ip string) {
			tlsConn, err := s.dialSingleTLS(raceCtx, ip, port, host, false)
			if err != nil {
				resCh <- raceResult{ip: ip, err: err}
				return
			}
			select {
			case <-raceCtx.Done():
				_ = tlsConn.Close()
			case resCh <- raceResult{conn: tlsConn, ip: ip}:
			}
		}(candidateIP)
	}

	var lastErr error
	for i := 0; i < len(candidates); i++ {
		select {
		case <-raceCtx.Done():
			if lastErr != nil {
				return nil, "", lastErr
			}
			return nil, "", raceCtx.Err()
		case res := <-resCh:
			if res.err == nil && res.conn != nil {
				cancel()
				s.workingIPMu.Lock()
				s.workingRelayIP = res.ip
				s.workingIPMu.Unlock()
				return res.conn, res.ip, nil
			}
			lastErr = res.err
		}
	}

	if lastErr == nil {
		lastErr = errors.New("Cloudflare не ответил")
	}
	return nil, "", lastErr
}

func (s *Server) tryDirectTCP(clientConn net.Conn, initialData []byte, dstHost string, dstPort int, id int64, fastMode bool) bool {
	timeout := 5 * time.Second
	if fastMode {
		timeout = 2 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	ip, err := s.doh.ResolveIPv4(ctx, dstHost)
	cancel()
	if err != nil {
		ip = dstHost
	}

	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 15 * time.Second}
	remoteConn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(dstPort)))
	if err != nil {
		return false
	}

	s.trackConn(remoteConn)
	defer func() {
		s.untrackConn(remoteConn)
		_ = remoteConn.Close()
	}()

	if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	if s.fragEnabled.Load() && len(initialData) > 5 && initialData[0] == 0x16 {
		chunks := [][]byte{initialData[:2], initialData[2:5], initialData[5:]}
		for i, ch := range chunks {
			if _, err := remoteConn.Write(ch); err != nil {
				return false
			}
			if i < len(chunks)-1 {
				time.Sleep(10 * time.Millisecond)
			}
		}
	} else {
		if _, err := remoteConn.Write(initialData); err != nil {
			return false
		}
	}

	replyWait := 4 * time.Second
	if fastMode {
		replyWait = 2500 * time.Millisecond
	}
	_ = remoteConn.SetReadDeadline(time.Now().Add(replyWait))
	firstReply := make([]byte, 16*1024)
	rn, rErr := remoteConn.Read(firstReply)
	_ = remoteConn.SetReadDeadline(time.Time{})

	if rn <= 0 || rErr != nil {
		return false
	}

	s.directBlockedUntil.Store(0)
	s.setStatus(fmt.Sprintf("Напрямую (%s)", dstHost))
	s.addLog("TCP", fmt.Sprintf("#%d Напрямую -> %s:%d", id, dstHost, dstPort))

	if _, err := clientConn.Write(firstReply[:rn]); err != nil {
		return true
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(remoteConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, remoteConn)
		done <- struct{}{}
	}()
	<-done
	return true
}

func (s *Server) dialTLSRace(ctx context.Context, addr string, dc int, timeout time.Duration) (net.Conn, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, "", err
	}

	s.workingIPMu.RLock()
	cachedIP := s.workingIPs[dc]
	s.workingIPMu.RUnlock()
	if cachedIP != "" {
		fastCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		conn, err := s.dialSingleTLS(fastCtx, cachedIP, port, host, true)
		cancel()
		if err == nil {
			return conn, cachedIP, nil
		}
		s.workingIPMu.Lock()
		delete(s.workingIPs, dc)
		s.workingIPMu.Unlock()
	}

	candidates := s.buildIPCandidates(ctx, host, dc)
	if len(candidates) == 0 {
		return nil, "", errors.New("нет кандидатов IP")
	}

	raceCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type raceResult struct {
		conn net.Conn
		ip   string
		err  error
	}

	resCh := make(chan raceResult, len(candidates))

	for _, candidateIP := range candidates {
		go func(ip string) {
			tlsConn, err := s.dialSingleTLS(raceCtx, ip, port, host, true)
			if err != nil {
				resCh <- raceResult{ip: ip, err: err}
				return
			}
			select {
			case <-raceCtx.Done():
				_ = tlsConn.Close()
			case resCh <- raceResult{conn: tlsConn, ip: ip}:
			}
		}(candidateIP)
	}

	var lastErr error
	for i := 0; i < len(candidates); i++ {
		select {
		case <-raceCtx.Done():
			if lastErr != nil {
				return nil, "", lastErr
			}
			return nil, "", raceCtx.Err()
		case res := <-resCh:
			if res.err == nil && res.conn != nil {
				cancel()
				s.workingIPMu.Lock()
				s.workingIPs[dc] = res.ip
				s.workingIPMu.Unlock()
				return res.conn, res.ip, nil
			}
			lastErr = res.err
		}
	}

	if lastErr == nil {
		lastErr = errors.New("ни один IP не ответил")
	}
	return nil, "", lastErr
}

func (s *Server) dialSingleTLS(ctx context.Context, ip, port, sni string, insecure bool) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 15 * time.Second,
	}
	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	var transportConn net.Conn = rawConn
	if s.fragEnabled.Load() {
		transportConn = &clientHelloFragConn{Conn: rawConn}
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify:          insecure,
		ServerName:                  sni,
		NextProtos:                  []string{"http/1.1"},
		MinVersion:                  tls.VersionTLS12,
		DynamicRecordSizingDisabled: true,
	}

	tlsConn := tls.Client(transportConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (s *Server) buildIPCandidates(ctx context.Context, host string, dc int) []string {
	seen := make(map[string]bool)
	var list []string
	add := func(ip string) {
		if ip != "" && !seen[ip] {
			seen[ip] = true
			list = append(list, ip)
		}
	}

	for _, poolIP := range dcIPPools[dc] {
		add(poolIP)
	}

	if s.doh.GetMode() != "fallback" {
		dnsCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
		if dnsIP, err := s.doh.ResolveIPv4(dnsCtx, host); err == nil {
			add(dnsIP)
		}
		cancel()
	}

	return list
}

type clientHelloFragConn struct {
	net.Conn
	fragmented bool
}

func (c *clientHelloFragConn) Write(b []byte) (int, error) {
	if !c.fragmented && len(b) > 5 {
		c.fragmented = true
		chunks := [][]byte{
			b[:2],
			b[2:5],
			b[5:],
		}
		for i, chunk := range chunks {
			if _, err := c.Conn.Write(chunk); err != nil {
				return 0, err
			}
			if i < len(chunks)-1 {
				time.Sleep(10 * time.Millisecond)
			}
		}
		return len(b), nil
	}
	return c.Conn.Write(b)
}
