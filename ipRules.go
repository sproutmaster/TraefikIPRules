package ipRule

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type Config struct {
	DenyList  []string `json:"denyList,omitempty"`
	AllowList []string `json:"allowList,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		DenyList:  make([]string, 0),
		AllowList: make([]string, 0),
	}
}

type IPProcessor struct {
	next       http.Handler
	name       string
	denyCIDRs  []*net.IPNet
	denyIPs    []net.IP
	allowCIDRs []*net.IPNet
	allowIPs   []net.IP
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	processor := &IPProcessor{
		next: next,
		name: name,
	}

	// Process deny rules
	for _, rule := range config.DenyList {
		if ip := net.ParseIP(rule); ip != nil {
			processor.denyIPs = append(processor.denyIPs, ip)
			continue
		}

		_, network, err := net.ParseCIDR(rule)
		if err != nil {
			return nil, err
		}
		processor.denyCIDRs = append(processor.denyCIDRs, network)
	}

	// Process allow rules
	for _, rule := range config.AllowList {
		if ip := net.ParseIP(rule); ip != nil {
			processor.allowIPs = append(processor.allowIPs, ip)
			continue
		}

		_, network, err := net.ParseCIDR(rule)
		if err != nil {
			return nil, err
		}
		processor.allowCIDRs = append(processor.allowCIDRs, network)
	}

	return processor, nil
}

// getIP extracts the client IP from the request
func (p *IPProcessor) getIP(req *http.Request) net.IP {
	// First try X-Forwarded-For header
	xff := req.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Get the first IP in the chain
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			if ip := net.ParseIP(strings.TrimSpace(ips[0])); ip != nil {
				return ip
			}
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// Try RemoteAddr as-is
		if ip := net.ParseIP(req.RemoteAddr); ip != nil {
			return ip
		}
		return nil
	}

	return net.ParseIP(host)
}

func (p *IPProcessor) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Get client IP
	clientIP := p.getIP(req)
	if clientIP == nil {
		http.Error(rw, "Invalid IP address", http.StatusForbidden)
		return
	}

	// Check deny rules first
	for _, denyIP := range p.denyIPs {
		if denyIP.Equal(clientIP) {
			http.Error(rw, "Access denied", http.StatusForbidden)
			return
		}
	}

	for _, denyCIDR := range p.denyCIDRs {
		if denyCIDR.Contains(clientIP) {
			http.Error(rw, "Access denied", http.StatusForbidden)
			return
		}
	}

	// If there are allow rules, the IP must match at least one
	if len(p.allowIPs) > 0 || len(p.allowCIDRs) > 0 {
		allowed := false

		for _, allowIP := range p.allowIPs {
			if allowIP.Equal(clientIP) {
				allowed = true
				break
			}
		}

		if !allowed {
			for _, allowCIDR := range p.allowCIDRs {
				if allowCIDR.Contains(clientIP) {
					allowed = true
					break
				}
			}
		}

		if !allowed {
			http.Error(rw, "Access denied", http.StatusForbidden)
			return
		}
	}

	p.next.ServeHTTP(rw, req)
}
