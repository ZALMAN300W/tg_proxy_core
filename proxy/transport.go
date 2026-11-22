package proxy

import (
	"context"
	"crypto/cipher"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var cfFallbackIPs = []string{
	"172.67.162.213",
	"104.21.82.196",
}

var (
	badRelayMu  sync.Mutex
	badRelayIPs = make(map[string]time.Time)
	zeroRxCount = make(map[string]int)
)

func clearBadRelayIPs() {
	badRelayMu.Lock()
	badRelayIPs = make(map[string]time.Time)
	zeroRxCount = make(map[string]int)
	badRelayMu.Unlock()
}

func markBadRelayIP(ip string, ttl time.Duration) {
	if ip == "" {
		return
	}
	badRelayMu.Lock()
	badRelayIPs[ip] = time.Now().Add(ttl)
	delete(zeroRxCount, ip)
	badRelayMu.Unlock()
}

func isBadRelayIP(ip string) bool {
	badRelayMu.Lock()
	defer badRelayMu.Unlock()
	until, ok := badRelayIPs[ip]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(badRelayIPs, ip)
		return false
	}
	return true
}

func (s *Server) recordRelayRx(ip string, rxBytes int64) bool {
	if ip == "" {
		return false
	}
	rotated := false
	badRelayMu.Lock()
	if rxBytes > 0 {
		delete(zeroRxCount, ip)
	} else {
		zeroRxCount[ip]++
		if zeroRxCount[ip] >= 2 {
			delete(zeroRxCount, ip)
			badRelayIPs[ip] = time.Now().Add(5 * time.Hour)
			rotated = true
		}
	}
	badRelayMu.Unlock()

	if rotated {
		s.workingIPMu.Lock()
		if s.workingRelayIP == ip {
			s.workingRelayIP = ""
		}
		s.workingIPMu.Unlock()
	}
	return rotated
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

// --- MTProto Proxy (с перешифрованием на лету) ---

func (s *Server) pumpMTProtoDirectWS(
	clientConn net.Conn,
	wsConn *websocket.Conn,
	sess *mtprotoSession,
	outInit []byte,
	upEnc, upDec cipher.Stream,
	host, usedIP string,
	id int64,
) {
	defer wsConn.Close()

	s.setStatus(fmt.Sprintf("Напрямую (%s)", usedIP))
	if sess.isMedia {
		s.addLog("DIRECT", fmt.Sprintf("#%d MTProto Медиа DC%d -> %s (%s)", id, sess.dc, host, usedIP))
	} else {
		s.addLog("DIRECT", fmt.Sprintf("#%d MTProto DC%d -> %s (%s)", id, sess.dc, host, usedIP))
	}

	_, _ = s.runMTProtoWSBridge(clientConn, wsConn, sess, outInit, upEnc, upDec, true)
}

func (s *Server) bridgeMTProtoWorker(
	clientConn net.Conn,
	sess *mtprotoSession,
	outInit []byte,
	upEnc, upDec cipher.Stream,
	id int64,
) {
	s.mu.RLock()
	relay := s.relayHost
	relayKey := s.relayKey
	s.mu.RUnlock()

	if relay == "" {
		return
	}

	mediaFlag := "0"
	if sess.isMedia {
		mediaFlag = "1"
	}

	wsURL := fmt.Sprintf("wss://%s/apiws?dc=%d&media=%s", trimRelayHost(relay), sess.dc, mediaFlag)
	if relayKey != "" {
		wsURL += "&key=" + url.QueryEscape(relayKey)
	}

	wsConn, usedIP, relayMode, ok := s.dialWorkerConn(wsURL, []string{"binary"}, fmt.Sprintf("DC%d", sess.dc), id)
	if !ok {
		return
	}
	defer wsConn.Close()

	isTCPFallback := relayMode == "tcp"
	tag := "CF-WS"
	if isTCPFallback {
		tag = "CF-TCP"
		s.setStatus(fmt.Sprintf("Cloudflare TCP (%s)", usedIP))
	} else {
		s.setStatus(fmt.Sprintf("Cloudflare WS (%s)", usedIP))
	}

	if sess.isMedia {
		s.addLog(tag, fmt.Sprintf("#%d MTProto Медиа DC%d (через %s)", id, sess.dc, usedIP))
	} else {
		s.addLog(tag, fmt.Sprintf("#%d MTProto DC%d (через %s)", id, sess.dc, usedIP))
	}

	rx, closeErr := s.runMTProtoWSBridge(clientConn, wsConn, sess, outInit, upEnc, upDec, !isTCPFallback)
	s.handleRelayClose(id, usedIP, rx, closeErr)
}

func (s *Server) bridgeMTProtoWorkerTCP(
	clientConn net.Conn,
	sess *mtprotoSession,
	outInit []byte,
	upEnc, upDec cipher.Stream,
	dstHost string,
	dstPort int,
	id int64,
) {
	s.mu.RLock()
	relay := s.relayHost
	relayKey := s.relayKey
	s.mu.RUnlock()

	if relay == "" {
		return
	}

	wsURL := fmt.Sprintf(
		"wss://%s/apiws?dst=%s&port=%d",
		trimRelayHost(relay),
		url.QueryEscape(dstHost),
		dstPort,
	)
	if relayKey != "" {
		wsURL += "&key=" + url.QueryEscape(relayKey)
	}

	wsConn, usedIP, _, ok := s.dialWorkerConn(wsURL, nil, fmt.Sprintf("%s:%d", dstHost, dstPort), id)
	if !ok {
		return
	}
	defer wsConn.Close()

	s.setStatus(fmt.Sprintf("Cloudflare CDN (%s)", usedIP))
	s.addLog("CF-TCP", fmt.Sprintf("#%d MTProto CDN DC%d -> %s:%d (через %s)", id, sess.dc, dstHost, dstPort, usedIP))

	rx, closeErr := s.runMTProtoWSBridge(clientConn, wsConn, sess, outInit, upEnc, upDec, false)
	s.handleRelayClose(id, usedIP, rx, closeErr)
}

func (s *Server) runMTProtoWSBridge(
	clientConn net.Conn,
	wsConn *websocket.Conn,
	sess *mtprotoSession,
	outInit []byte,
	upEnc, upDec cipher.Stream,
	useSplitter bool,
) (int64, error) {
	const pongWait = 65 * time.Second
	const pingPeriod = 30 * time.Second

	s.trackConn(wsConn)
	defer s.untrackConn(wsConn)

	_ = wsConn.SetReadDeadline(time.Now().Add(pongWait))
	wsConn.SetPongHandler(func(string) error {
		_ = wsConn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	if len(outInit) > 0 {
		_ = wsConn.SetWriteDeadline(time.Now().Add(8 * time.Second))
		if err := wsConn.WriteMessage(websocket.BinaryMessage, outInit); err != nil {
			return 0, err
		}
		_ = wsConn.SetWriteDeadline(time.Time{})
	}

	var writeMu sync.Mutex
	var closeOnce sync.Once
	var closing atomic.Bool
	var rxBytes atomic.Int64

	var wsErrMu sync.Mutex
	var wsErr error
	setWSErr := func(err error) {
		if err == nil {
			return
		}
		wsErrMu.Lock()
		if wsErr == nil {
			wsErr = err
		}
		wsErrMu.Unlock()
	}

	done := make(chan struct{})
	shutdown := func() {
		closeOnce.Do(func() {
			closing.Store(true)
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
					if !closing.Load() {
						setWSErr(err)
					}
					shutdown()
					return
				}
			}
		}
	}()

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		defer shutdown()
		for {
			msgType, data, err := wsConn.ReadMessage()
			if err != nil {
				if !closing.Load() {
					setWSErr(err)
				}
				return
			}
			_ = wsConn.SetReadDeadline(time.Now().Add(pongWait))
			if msgType != websocket.BinaryMessage || len(data) == 0 {
				continue
			}
			rxBytes.Add(int64(len(data)))
			upDec.XORKeyStream(data, data)
			sess.clientEnc.XORKeyStream(data, data)
			if _, err := clientConn.Write(data); err != nil {
				return
			}
		}
	}()

	var splitter *plainMTProtoSplitter
	if useSplitter {
		splitter = newPlainMTProtoSplitter(sess.protoID)
	}

	buf := make([]byte, 64*1024)
	for {
		n, err := clientConn.Read(buf)
		if n > 0 {
			plain := make([]byte, n)
			sess.clientDec.XORKeyStream(plain, buf[:n])

			var frames [][]byte
			if splitter != nil {
				frames = splitter.Push(plain)
			} else {
				frames = [][]byte{plain}
			}

			for _, frame := range frames {
				upEnc.XORKeyStream(frame, frame)
				writeMu.Lock()
				_ = wsConn.SetWriteDeadline(time.Now().Add(8 * time.Second))
				wErr := wsConn.WriteMessage(websocket.BinaryMessage, frame)
				_ = wsConn.SetWriteDeadline(time.Time{})
				writeMu.Unlock()
				if wErr != nil {
					if !closing.Load() {
						setWSErr(wErr)
					}
					shutdown()
					<-readDone
					wsErrMu.Lock()
					outErr := wsErr
					wsErrMu.Unlock()
					return rxBytes.Load(), outErr
				}
			}
		}
		if err != nil {
			break
		}
	}

	shutdown()
	<-readDone
	wsErrMu.Lock()
	outErr := wsErr
	wsErrMu.Unlock()
	return rxBytes.Load(), outErr
}

// --- Legacy SOCKS5 ---

func (s *Server) pumpDirectWebSocket(clientConn net.Conn, wsConn *websocket.Conn, initPacket []byte, info mtprotoInit, host, usedIP string, id int64) {
	defer wsConn.Close()

	s.setStatus(fmt.Sprintf("Напрямую (%s)", usedIP))
	if info.isMedia {
		s.addLog("DIRECT", fmt.Sprintf("#%d Медиа -> %s (%s)", id, host, usedIP))
	} else {
		s.addLog("DIRECT", fmt.Sprintf("#%d Туннель -> %s (%s)", id, host, usedIP))
	}

	splitter := newMTProtoSplitter(info.protoID, info.stream)
	_, _ = s.runWebSocketBridge(clientConn, wsConn, initPacket, splitter)
}

func (s *Server) bridgeWorkerDC(clientConn net.Conn, initPacket []byte, info mtprotoInit, id int64) {
	s.mu.RLock()
	relay := s.relayHost
	relayKey := s.relayKey
	s.mu.RUnlock()

	if relay == "" {
		return
	}

	mediaFlag := "0"
	if info.isMedia {
		mediaFlag = "1"
	}

	wsURL := fmt.Sprintf("wss://%s/apiws?dc=%d&media=%s", trimRelayHost(relay), info.dc, mediaFlag)
	if relayKey != "" {
		wsURL += "&key=" + url.QueryEscape(relayKey)
	}

	wsConn, usedIP, relayMode, ok := s.dialWorkerConn(wsURL, []string{"binary"}, fmt.Sprintf("DC%d", info.dc), id)
	if !ok {
		return
	}
	defer wsConn.Close()

	tag := "CF-WS"
	var splitter *mtprotoSplitter
	if relayMode == "tcp" {
		tag = "CF-TCP"
		s.setStatus(fmt.Sprintf("Cloudflare TCP (%s)", usedIP))
	} else {
		s.setStatus(fmt.Sprintf("Cloudflare WS (%s)", usedIP))
		splitter = newMTProtoSplitter(info.protoID, info.stream)
	}
	s.addLog(tag, fmt.Sprintf("#%d DC%d (media=%s) через %s", id, info.dc, mediaFlag, usedIP))

	rx, closeErr := s.runWebSocketBridge(clientConn, wsConn, initPacket, splitter)
	s.handleRelayClose(id, usedIP, rx, closeErr)
}

func (s *Server) bridgeWorkerTCP(clientConn net.Conn, initialData []byte, dstHost string, dstPort int, id int64) {
	s.mu.RLock()
	relay := s.relayHost
	relayKey := s.relayKey
	s.mu.RUnlock()

	if relay == "" {
		return
	}

	wsURL := fmt.Sprintf(
		"wss://%s/apiws?dst=%s&port=%d",
		trimRelayHost(relay),
		url.QueryEscape(dstHost),
		dstPort,
	)
	if relayKey != "" {
		wsURL += "&key=" + url.QueryEscape(relayKey)
	}

	wsConn, usedIP, _, ok := s.dialWorkerConn(wsURL, nil, fmt.Sprintf("%s:%d", dstHost, dstPort), id)
	if !ok {
		return
	}
	defer wsConn.Close()

	s.setStatus(fmt.Sprintf("Cloudflare TCP (%s)", usedIP))
	s.addLog("CF-TCP", fmt.Sprintf("#%d TCP -> %s:%d (через %s)", id, dstHost, dstPort, usedIP))

	rx, closeErr := s.runWebSocketBridge(clientConn, wsConn, initialData, nil)
	s.handleRelayClose(id, usedIP, rx, closeErr)
}

func (s *Server) handleRelayClose(id int64, usedIP string, rx int64, closeErr error) {
	if rx > 0 {
		s.recordRelayRx(usedIP, rx)
		return
	}
	if websocket.IsCloseError(closeErr, websocket.CloseNormalClosure) {
		return
	}
	rotated := s.recordRelayRx(usedIP, 0)
	reason := "нет ответа от сервера (клиент закрыл)"
	if closeErr != nil {
		reason = closeErr.Error()
	}
	if rotated {
		s.addLog("WARN", fmt.Sprintf("#%d CF (%s) rx=0: %s — смена узла", id, usedIP, reason))
	} else {
		s.addLog("WARN", fmt.Sprintf("#%d CF (%s) rx=0: %s", id, usedIP, reason))
	}
}

func (s *Server) dialWorkerConn(wsURL string, subprotocols []string, targetLabel string, id int64) (*websocket.Conn, string, string, bool) {
	if waitUntil := s.cfBackoffUntil.Load(); waitUntil > 0 {
		if rem := time.Until(time.Unix(0, waitUntil)); rem > 0 {
			if rem > 4*time.Second {
				rem = 4 * time.Second
			}
			time.Sleep(rem)
		}
	}

	var usedIP string
	dialer := websocket.Dialer{
		Subprotocols:      subprotocols,
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

	reqHeaders := http.Header{}
	reqHeaders.Set("User-Agent", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")

	select {
	case s.cfDialSem <- struct{}{}:
	case <-time.After(5 * time.Second):
		return nil, "", "", false
	}
	wsConn, resp, err := dialer.Dial(wsURL, reqHeaders)
	time.Sleep(80 * time.Millisecond)
	<-s.cfDialSem

	statusInfo := ""
	relayMode := "ws"
	if resp != nil {
		statusInfo = fmt.Sprintf(" (HTTP %d)", resp.StatusCode)
		if m := resp.Header.Get("X-Relay-Mode"); m != "" {
			relayMode = m
		}
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		if resp.StatusCode == 403 || resp.StatusCode == 429 || resp.StatusCode >= 500 {
			s.workingIPMu.Lock()
			if s.workingRelayIP == usedIP {
				s.workingRelayIP = ""
			}
			s.workingIPMu.Unlock()

			if resp.StatusCode == 403 && usedIP != "" {
				markBadRelayIP(usedIP, 5*time.Hour)
			} else {
				s.cfBackoffUntil.Store(time.Now().Add(4 * time.Second).UnixNano())
			}
		}
	}
	if err != nil {
		if resp == nil && usedIP != "" {
			s.workingIPMu.Lock()
			if s.workingRelayIP == usedIP {
				s.workingRelayIP = ""
			}
			s.workingIPMu.Unlock()
			markBadRelayIP(usedIP, 30*time.Minute)
		}
		via := ""
		if usedIP != "" {
			via = " via " + usedIP
		}
		s.setStatus("Ошибка Cloudflare" + statusInfo)
		s.addLog("ERR", fmt.Sprintf("#%d CF -> %s%s: %v%s", id, targetLabel, via, err, statusInfo))
		time.Sleep(1200 * time.Millisecond)
		return nil, "", "", false
	}
	return wsConn, usedIP, relayMode, true
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

func (s *Server) runWebSocketBridge(clientConn net.Conn, wsConn *websocket.Conn, initialData []byte, splitter *mtprotoSplitter) (int64, error) {
	const pongWait = 65 * time.Second
	const pingPeriod = 30 * time.Second

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
			return 0, err
		}
		_ = wsConn.SetWriteDeadline(time.Time{})
	}

	var writeMu sync.Mutex
	var closeOnce sync.Once
	var closing atomic.Bool
	var rxBytes atomic.Int64

	var wsErrMu sync.Mutex
	var wsErr error
	setWSErr := func(err error) {
		if err == nil {
			return
		}
		wsErrMu.Lock()
		if wsErr == nil {
			wsErr = err
		}
		wsErrMu.Unlock()
	}

	done := make(chan struct{})
	shutdown := func() {
		closeOnce.Do(func() {
			closing.Store(true)
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
					if !closing.Load() {
						setWSErr(err)
					}
					shutdown()
					return
				}
			}
		}
	}()

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		defer shutdown()
		for {
			msgType, data, err := wsConn.ReadMessage()
			if err != nil {
				if !closing.Load() {
					setWSErr(err)
				}
				return
			}
			_ = wsConn.SetReadDeadline(time.Now().Add(pongWait))
			if msgType != websocket.BinaryMessage {
				continue
			}
			rxBytes.Add(int64(len(data)))
			if _, err := clientConn.Write(data); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 64*1024)
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
					if !closing.Load() {
						setWSErr(wErr)
					}
					shutdown()
					<-readDone
					wsErrMu.Lock()
					outErr := wsErr
					wsErrMu.Unlock()
					return rxBytes.Load(), outErr
				}
			}
		}
		if err != nil {
			break
		}
	}

	shutdown()
	<-readDone
	wsErrMu.Lock()
	outErr := wsErr
	wsErrMu.Unlock()
	return rxBytes.Load(), outErr
}

func (s *Server) dialRelayTLS(ctx context.Context, addr string) (net.Conn, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, "", err
	}

	s.workingIPMu.RLock()
	cachedRelay := s.workingRelayIP
	s.workingIPMu.RUnlock()

	if cachedRelay != "" && !isBadRelayIP(cachedRelay) {
		fastCtx, cancel := context.WithTimeout(ctx, 1800*time.Millisecond)
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

	dnsCtx, cancelDNS := context.WithTimeout(ctx, 1500*time.Millisecond)
	dnsIPs := s.doh.ResolveAllIPv4(dnsCtx, host)
	cancelDNS()

	buildList := func(skipBad bool) []string {
		seen := make(map[string]bool)
		var out []string
		add := func(ip string) {
			if ip == "" || ip == cachedRelay || seen[ip] {
				return
			}
			if skipBad && isBadRelayIP(ip) {
				return
			}
			seen[ip] = true
			out = append(out, ip)
		}
		for _, ip := range dnsIPs {
			add(ip)
		}
		for _, fb := range cfFallbackIPs {
			add(fb)
		}
		return out
	}

	candidates := buildList(true)
	if len(candidates) == 0 {
		candidates = buildList(false)
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
