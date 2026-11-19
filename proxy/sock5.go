package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

func (s *Server) handleClient(clientConn net.Conn, id int64) {
	s.trackConn(clientConn)
	defer func() {
		s.untrackConn(clientConn)
		_ = clientConn.Close()
	}()

	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	dstHost, dstPort, err := performSocks5Handshake(clientConn)
	if err != nil {
		s.addLog("ERR", fmt.Sprintf("#%d SOCKS5: %v", id, err))
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

	// 1. Стандартный Obfuscated2 MTProto (DC 1..5)
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

			s.bridgeWorkerTCP(clientConn, initBuf, dstHost, dstPort, id)
			return
		}
	}

	// 2. FakeTLS / обычный TLS: дочитываем запись ClientHello целиком, чтобы избежать дедлока
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

	// 3. FakeTLS и медиа-CDN (149.154.167.50:443, 91.105.192.100:443 и т.д.)
	if !skipDirect {
		if s.tryDirectTCP(clientConn, initialData, dstHost, dstPort, id, hasRelay) {
			return
		}
		// Не включаем cooldown из-за IPv6, так как у большинства провайдеров его нет
		if hasRelay && !isIPv6Host(dstHost) {
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

func performSocks5Handshake(conn net.Conn) (string, int, error) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}
	if header[0] != 0x05 {
		return "", 0, errors.New("неверная версия SOCKS")
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", 0, err
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

	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(reply); err != nil {
		return "", 0, err
	}

	return host, port, nil
}
