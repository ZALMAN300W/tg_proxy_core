package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

var errIgnoredHost = errors.New("ignored non-telegram host")

var cdnDCHosts = map[int]string{
	203: "91.105.192.100",
}

func (s *Server) handleClient(clientConn net.Conn, id int64) {
	s.trackConn(clientConn)
	defer func() {
		s.untrackConn(clientConn)
		_ = clientConn.Close()
	}()

	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	firstBuf := make([]byte, 64)
	n, err := clientConn.Read(firstBuf)
	if err != nil || n == 0 {
		return
	}

	// Автоопределение SOCKS5 (клиент шлёт 3..10 байт и ждёт ответ) vs MTProto (64 байта сразу)
	if n >= 3 && n <= 10 && firstBuf[0] == 0x05 && int(firstBuf[1]) == n-2 {
		s.handleSocks5Client(clientConn, firstBuf[:n], id)
		return
	}

	if n < 64 {
		if _, err := io.ReadFull(clientConn, firstBuf[n:64]); err != nil {
			return
		}
	}
	_ = clientConn.SetReadDeadline(time.Time{})

	s.handleMTProtoClient(clientConn, firstBuf, id)
}

func (s *Server) handleMTProtoClient(clientConn net.Conn, initBuf []byte, id int64) {
	s.mu.RLock()
	secret := s.mtprotoSecret
	relay := s.relayHost
	s.mu.RUnlock()

	sess, err := parseMTProtoClientInit(initBuf, secret)
	if err != nil {
		s.addLog("ERR", fmt.Sprintf("#%d MTProto: %v", id, err))
		return
	}

	outInit, upEnc, upDec, err := buildUpstreamInit(sess.tag, sess.rawDC)
	if err != nil {
		s.addLog("ERR", fmt.Sprintf("#%d MTProto init: %v", id, err))
		return
	}

	hasRelay := relay != ""
	skipDirect := hasRelay && s.isDirectInCooldown()

	// Основные дата-центры DC 1..5 (включая медиа -1..-5) -> /apiws с 0 мс CPU на Cloudflare
	if sess.dc >= 1 && sess.dc <= 5 {
		if !skipDirect {
			wsConn, usedHost, usedIP, dialErr := s.dialDirectWebSocket(sess.dc, sess.isMedia, hasRelay)
			if dialErr == nil {
				s.directBlockedUntil.Store(0)
				s.pumpMTProtoDirectWS(clientConn, wsConn, sess, outInit, upEnc, upDec, usedHost, usedIP, id)
				return
			}
			if !hasRelay {
				s.setStatus("Ошибка прямого канала")
				s.addLog("ERR", fmt.Sprintf("#%d MTProto DC%d direct: %v", id, sess.dc, dialErr))
				return
			}
			s.markDirectUnavailable()
		}

		s.bridgeMTProtoWorker(clientConn, sess, outInit, upEnc, upDec, id)
		return
	}

	// Редкий случай: CDN-датацентр (например DC 203 -> 91.105.192.100)
	if cdnIP, ok := cdnDCHosts[sess.dc]; ok && hasRelay {
		s.bridgeMTProtoWorkerTCP(clientConn, sess, outInit, upEnc, upDec, cdnIP, 443, id)
		return
	}

	s.addLog("WARN", fmt.Sprintf("#%d MTProto неизвестный DC%d (raw=%d)", id, sess.dc, sess.rawDC))
}

func (s *Server) handleSocks5Client(clientConn net.Conn, greeting []byte, id int64) {
	dstHost, dstPort, err := performSocks5Handshake(clientConn, greeting)
	if err != nil {
		if !errors.Is(err, errIgnoredHost) {
			s.addLog("ERR", fmt.Sprintf("#%d SOCKS5: %v", id, err))
		}
		return
	}
	if dstPort == 0 {
		dstPort = 443
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	initBuf := make([]byte, 64)
	n, readErr := io.ReadFull(clientConn, initBuf)

	if n == 0 {
		_ = clientConn.SetReadDeadline(time.Time{})
		return
	}

	s.mu.RLock()
	relay := s.relayHost
	s.mu.RUnlock()
	hasRelay := relay != ""
	skipDirect := hasRelay && s.isDirectInCooldown()

	if n == 64 && readErr == nil {
		if info, ok := parseObfuscatedInit(initBuf, dstHost); ok && info.dc >= 1 && info.dc <= 5 {
			_ = clientConn.SetReadDeadline(time.Time{})

			if !skipDirect {
				wsConn, usedHost, usedIP, dialErr := s.dialDirectWebSocket(info.dc, info.isMedia, hasRelay)
				if dialErr == nil {
					s.directBlockedUntil.Store(0)
					s.pumpDirectWebSocket(clientConn, wsConn, initBuf, info, usedHost, usedIP, id)
					return
				}
				if !hasRelay {
					s.setStatus("Ошибка прямого канала")
					s.addLog("ERR", fmt.Sprintf("#%d DC%d direct: %v", id, info.dc, dialErr))
					return
				}
				s.markDirectUnavailable()
			}

			s.bridgeWorkerDC(clientConn, initBuf, info, id)
			return
		}
	}

	initialData := initBuf[:n]
	if n >= 5 && initialData[0] == 0x16 && initialData[1] == 0x03 {
		recordLen := int(binary.BigEndian.Uint16(initialData[3:5]))
		totalLen := 5 + recordLen
		if totalLen > n && totalLen <= 16384+5 {
			fullBuf := make([]byte, totalLen)
			copy(fullBuf, initialData)
			more, _ := io.ReadFull(clientConn, fullBuf[n:])
			initialData = fullBuf[:n+more]
		}
	}
	_ = clientConn.SetReadDeadline(time.Time{})

	if isIPv6Host(dstHost) {
		if !skipDirect {
			_ = s.tryDirectTCP(clientConn, initialData, dstHost, dstPort, id, hasRelay)
		}
		return
	}

	if !skipDirect {
		if s.tryDirectTCP(clientConn, initialData, dstHost, dstPort, id, hasRelay) {
			return
		}
		if hasRelay {
			s.markDirectUnavailable()
		}
	}

	if hasRelay {
		s.bridgeWorkerTCP(clientConn, initialData, dstHost, dstPort, id)
	}
}

func isIPv6Host(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

func isBlockedNonTelegramIPv4(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return false
	}
	prefixes := []string{
		"149.154.",
		"91.108.",
		"91.105.192.",
		"91.105.193.",
		"185.76.151.",
		"95.161.",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(host, p) {
			return false
		}
	}
	return true
}

func performSocks5Handshake(conn net.Conn, greeting []byte) (string, int, error) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	if len(greeting) < 3 || greeting[0] != 0x05 {
		return "", 0, errors.New("неверная версия SOCKS")
	}

	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", 0, err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return "", 0, err
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", 0, errors.New("неподдерживаемая команда")
	}

	var host string
	switch req[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", 0, err
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", 0, err
		}
		host = string(domain)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	default:
		return "", 0, errors.New("неизвестный тип адреса")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, err
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	if isBlockedNonTelegramIPv4(host) {
		_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
		var b [1]byte
		_, _ = conn.Read(b[:])
		_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return "", 0, errIgnoredHost
	}

	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		return "", 0, err
	}

	return host, port, nil
}
