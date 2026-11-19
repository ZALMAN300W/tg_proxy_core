package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type dohResolver struct {
	mu      sync.RWMutex
	mode    string
	cache   map[string]dohCacheEntry
	clients map[string]*http.Client
}

type dohCacheEntry struct {
	ips       []string
	expiresAt time.Time
}

func newDoHResolver() *dohResolver {
	snis := []string{"dns.google", "dns.alidns.com", "cloudflare-dns.com"}
	clients := make(map[string]*http.Client, len(snis))
	for _, sni := range snis {
		clients[sni] = &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{ServerName: sni},
				MaxIdleConns:    4,
				IdleConnTimeout: 30 * time.Second,
			},
		}
	}
	return &dohResolver{
		mode:    "auto",
		cache:   make(map[string]dohCacheEntry),
		clients: clients,
	}
}

func (r *dohResolver) SetMode(mode string) {
	r.mu.Lock()
	r.mode = mode
	r.cache = make(map[string]dohCacheEntry)
	r.mu.Unlock()
	r.closeIdleConnections()
}

func (r *dohResolver) ClearCache() {
	r.mu.Lock()
	r.cache = make(map[string]dohCacheEntry)
	r.mu.Unlock()
	r.closeIdleConnections()
}

func (r *dohResolver) closeIdleConnections() {
	for _, c := range r.clients {
		c.CloseIdleConnections()
	}
}

func (r *dohResolver) GetMode() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.mode
}

func (r *dohResolver) ResolveIPv4(ctx context.Context, host string) (string, error) {
	ips := r.ResolveAllIPv4(ctx, host)
	if len(ips) == 0 {
		return "", fmt.Errorf("не удалось определить IP для %s", host)
	}
	return ips[0], nil
}

func (r *dohResolver) ResolveAllIPv4(ctx context.Context, host string) []string {
	if parsed := net.ParseIP(host); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return []string{v4.String()}
		}
		return []string{host}
	}

	r.mu.RLock()
	mode := r.mode
	entry, found := r.cache[host]
	r.mu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) && len(entry.ips) > 0 {
		return entry.ips
	}

	type dohEndpoint struct {
		url string
		sni string
	}

	var endpoints []dohEndpoint
	switch mode {
	case "google":
		endpoints = []dohEndpoint{{fmt.Sprintf("https://8.8.8.8/resolve?name=%s&type=A", host), "dns.google"}}
	case "alidns":
		endpoints = []dohEndpoint{{fmt.Sprintf("https://223.5.5.5/resolve?name=%s&type=A", host), "dns.alidns.com"}}
	case "cloudflare":
		endpoints = []dohEndpoint{{fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=A", host), "cloudflare-dns.com"}}
	default:
		endpoints = []dohEndpoint{
			{fmt.Sprintf("https://8.8.8.8/resolve?name=%s&type=A", host), "dns.google"},
			{fmt.Sprintf("https://223.5.5.5/resolve?name=%s&type=A", host), "dns.alidns.com"},
			{fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=A", host), "cloudflare-dns.com"},
		}
	}

	raceCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	type dnsResult struct {
		ips []string
		ttl time.Duration
		err error
	}

	totalTasks := len(endpoints)
	if mode == "auto" {
		totalTasks++
	}
	resCh := make(chan dnsResult, totalTasks)

	for _, ep := range endpoints {
		go func(e dohEndpoint) {
			ips, ttl, err := r.queryDoHAll(raceCtx, e.url, e.sni)
			resCh <- dnsResult{ips: ips, ttl: ttl, err: err}
		}(ep)
	}

	if mode == "auto" {
		go func() {
			ips, err := net.DefaultResolver.LookupIP(raceCtx, "ip4", host)
			if err != nil || len(ips) == 0 {
				resCh <- dnsResult{err: errors.New("system dns failed")}
				return
			}
			var out []string
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					out = append(out, v4.String())
				}
			}
			if len(out) == 0 {
				resCh <- dnsResult{err: errors.New("no ipv4")}
				return
			}
			resCh <- dnsResult{ips: out, ttl: 10 * time.Minute}
		}()
	}

raceLoop:
	for i := 0; i < totalTasks; i++ {
		select {
		case <-raceCtx.Done():
			break raceLoop
		case res := <-resCh:
			if res.err == nil && len(res.ips) > 0 {
				cancel()
				ttl := res.ttl
				if ttl < 10*time.Minute {
					ttl = 10 * time.Minute
				}
				r.mu.Lock()
				r.cache[host] = dohCacheEntry{ips: res.ips, expiresAt: time.Now().Add(ttl)}
				r.mu.Unlock()
				return res.ips
			}
		}
	}

	if found {
		return entry.ips
	}
	return nil
}

func (r *dohResolver) queryDoHAll(ctx context.Context, reqURL, sni string) ([]string, time.Duration, error) {
	client := r.clients[sni]
	if client == nil {
		return nil, 0, fmt.Errorf("неизвестный DoH клиент %s", sni)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	var dnsResp struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
			TTL  int    `json:"TTL"`
		} `json:"Answer"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err := json.Unmarshal(body, &dnsResp); err != nil {
		return nil, 0, err
	}

	var ips []string
	var minTTL time.Duration
	for _, ans := range dnsResp.Answer {
		if ans.Type == 1 && net.ParseIP(ans.Data) != nil {
			ips = append(ips, ans.Data)
			t := time.Duration(ans.TTL) * time.Second
			if minTTL == 0 || t < minTTL {
				minTTL = t
			}
		}
	}
	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("нет A-записи от %s", sni)
	}
	return ips, minTTL, nil
}
