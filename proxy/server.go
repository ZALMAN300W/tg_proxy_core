package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const directCooldownDuration = 60 * time.Second

type Server struct {
	listenAddr  string
	listener    net.Listener
	doh         *dohResolver
	mu          sync.RWMutex
	running     bool
	lastStatus  string
	connCount   atomic.Int64
	fragEnabled atomic.Bool
	relayHost   string
	relayKey    string

	directBlockedUntil atomic.Int64

	workingIPMu    sync.RWMutex
	workingIPs     map[int]string
	workingRelayIP string

	activeConns sync.Map

	logMu sync.Mutex
	logs  []string
}

func NewServer(listenAddr string) *Server {
	s := &Server{
		listenAddr: listenAddr,
		doh:        newDoHResolver(),
		lastStatus: "Остановлен",
		workingIPs: make(map[int]string),
	}
	s.fragEnabled.Store(true)
	return s
}

func (s *Server) addLog(tag, msg string) {
	ts := time.Now().Format("15:04:05")
	line := fmt.Sprintf("[%s] [%s] %s", ts, tag, msg)

	s.logMu.Lock()
	s.logs = append(s.logs, line)
	if len(s.logs) > 120 {
		s.logs = s.logs[len(s.logs)-120:]
	}
	s.logMu.Unlock()
}

func (s *Server) GetLogs() string {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	if len(s.logs) == 0 {
		return "Логи пока пусты..."
	}
	return strings.Join(s.logs, "\n")
}

func (s *Server) ClearLogs() {
	s.logMu.Lock()
	s.logs = nil
	s.logMu.Unlock()
	s.addLog("SYS", "Журнал очищен")
}

func (s *Server) SetDoHMode(mode string) {
	s.doh.SetMode(mode)
	s.workingIPMu.Lock()
	s.workingIPs = make(map[int]string)
	s.workingRelayIP = ""
	s.workingIPMu.Unlock()
	s.directBlockedUntil.Store(0)
	s.addLog("CFG", "Режим DNS: "+mode)
}

func (s *Server) SetFragmentation(enabled bool) {
	s.fragEnabled.Store(enabled)
	s.directBlockedUntil.Store(0)
	state := "выкл"
	if enabled {
		state = "вкл"
	}
	s.addLog("CFG", "Фрагментация пакетов: "+state)
}

func (s *Server) SetRelayHost(host string) {
	s.mu.Lock()
	s.relayHost = strings.TrimSpace(host)
	s.mu.Unlock()
	s.workingIPMu.Lock()
	s.workingRelayIP = ""
	s.workingIPMu.Unlock()
	s.directBlockedUntil.Store(0)
	if host != "" {
		s.addLog("CFG", "Резервный Cloudflare: "+host+" (сначала напрямую)")
	}
}

func (s *Server) SetRelayKey(key string) {
	s.mu.Lock()
	s.relayKey = strings.TrimSpace(key)
	s.mu.Unlock()
	if key != "" {
		s.addLog("CFG", "Ключ ретранслятора: задан")
	}
}

// OnNetworkChanged вызывается из Android при смене Wi-Fi <-> 4G:
// сбрасывает DNS/IP-кэши, паузу Cloudflare и закрывает зависшие старые сокеты.
func (s *Server) OnNetworkChanged() {
	s.doh.ClearCache()
	s.workingIPMu.Lock()
	s.workingIPs = make(map[int]string)
	s.workingRelayIP = ""
	s.workingIPMu.Unlock()
	s.directBlockedUntil.Store(0)

	closed := s.closeAllActiveConns()
	s.addLog("NET", fmt.Sprintf("Смена сети — сброс маршрутов (закрыто сокетов: %d)", closed))
}

func (s *Server) trackConn(c io.Closer) {
	if c != nil {
		s.activeConns.Store(c, struct{}{})
	}
}

func (s *Server) untrackConn(c io.Closer) {
	if c != nil {
		s.activeConns.Delete(c)
	}
}

func (s *Server) closeAllActiveConns() int {
	closed := 0
	s.activeConns.Range(func(key, _ any) bool {
		if c, ok := key.(io.Closer); ok {
			_ = c.Close()
			closed++
		}
		s.activeConns.Delete(key)
		return true
	})
	return closed
}

func (s *Server) setStatus(status string) {
	s.mu.Lock()
	s.lastStatus = status
	s.mu.Unlock()
}

func (s *Server) GetStats() string {
	s.mu.RLock()
	st := s.lastStatus
	s.mu.RUnlock()
	return fmt.Sprintf("Запросов от ТГ: %d | %s", s.connCount.Load(), st)
}

func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("proxy already running")
	}

	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		s.mu.Unlock()
		s.setStatus("Ошибка порта: " + err.Error())
		s.addLog("ERR", "Не удалось открыть "+s.listenAddr+": "+err.Error())
		return fmt.Errorf("listen %s: %w", s.listenAddr, err)
	}
	s.listener = ln
	s.running = true
	s.directBlockedUntil.Store(0)
	s.mu.Unlock()

	s.setStatus("Активен (" + s.listenAddr + ")")
	s.addLog("SYS", "Прокси запущен на "+s.listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.RLock()
			stillRunning := s.running
			s.mu.RUnlock()
			if !stillRunning {
				return nil
			}
			continue
		}
		id := s.connCount.Add(1)
		go s.handleClient(conn, id)
	}
}

func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.lastStatus = "Остановлен"
	ln := s.listener
	s.mu.Unlock()

	s.closeAllActiveConns()
	s.doh.ClearCache()
	s.addLog("SYS", "Прокси остановлен")

	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *Server) isDirectInCooldown() bool {
	return time.Now().UnixNano() < s.directBlockedUntil.Load()
}

func (s *Server) markDirectUnavailable() {
	now := time.Now()
	prev := s.directBlockedUntil.Load()
	until := now.Add(directCooldownDuration).UnixNano()
	s.directBlockedUntil.Store(until)
	if now.UnixNano() >= prev {
		s.addLog("AUTO", "Прямой канал нестабилен — переход на Cloudflare на 60 сек")
	}
}
