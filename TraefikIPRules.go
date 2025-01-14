package TraefikIPRules

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type Config struct {
	Deny       []string `json:"deny,omitempty"`
	Allow      []string `json:"allow,omitempty"`
	Precedence string   `json:"precedence,omitempty"` // "allow" or "deny"
}

type ipRange struct {
	start net.IP
	end   net.IP
}

func CreateConfig() *Config {
	return &Config{
		Deny:       make([]string, 0),
		Allow:      make([]string, 0),
		Precedence: "deny", // Default to deny
	}
}

type IPProcessor struct {
	next        http.Handler
	name        string
	denyCIDRs   []*net.IPNet
	denyIPs     []net.IP
	denyRanges  []ipRange
	allowCIDRs  []*net.IPNet
	allowIPs    []net.IP
	allowRanges []ipRange
	precedence  string
}

func parseIPRange(ipRangeStr string) (*ipRange, error) {
	parts := strings.Split(ipRangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format: %s", ipRangeStr)
	}

	start := net.ParseIP(strings.TrimSpace(parts[0]))
	end := net.ParseIP(strings.TrimSpace(parts[1]))

	if start == nil || end == nil {
		return nil, fmt.Errorf("invalid IP address in range: %s", ipRangeStr)
	}

	if start.To4() == nil || end.To4() == nil {
		return nil, fmt.Errorf("only IPv4 ranges are supported: %s", ipRangeStr)
	}

	for i := 0; i < len(start.To4()); i++ {
		if start.To4()[i] > end.To4()[i] {
			return nil, fmt.Errorf("invalid range: start IP must be less than end IP")
		}
		if start.To4()[i] < end.To4()[i] {
			break
		}
	}

	return &ipRange{
		start: start.To4(),
		end:   end.To4(),
	}, nil
}

func (r *ipRange) IPRangeContains(ip net.IP) bool {
	if ip.To4() == nil {
		return false
	}

	ip = ip.To4()
	for i := 0; i < 4; i++ {
		if ip[i] < r.start[i] || ip[i] > r.end[i] {
			return false
		}
		if ip[i] > r.start[i] || ip[i] < r.end[i] {
			break
		}
	}
	return true
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.Precedence != "" && config.Precedence != "allow" && config.Precedence != "deny" {
		return nil, fmt.Errorf("invalid precedence value: %s. Must be either 'allow' or 'deny'", config.Precedence)
	}

	processor := &IPProcessor{
		next:       next,
		name:       name,
		precedence: config.Precedence,
	}

	// Process deny rules
	for _, rule := range config.Deny {
		// Try parsing as a single IP
		if ip := net.ParseIP(rule); ip != nil {
			processor.denyIPs = append(processor.denyIPs, ip)
			continue
		}

		// Try parsing as CIDR
		_, network, err := net.ParseCIDR(rule)
		if err == nil {
			processor.denyCIDRs = append(processor.denyCIDRs, network)
			continue
		}

		// Try parsing as IP range
		ipRange, err := parseIPRange(rule)
		if err == nil {
			processor.denyRanges = append(processor.denyRanges, *ipRange)
			continue
		}

		return nil, fmt.Errorf("invalid IP, CIDR, or range in deny list: %s", rule)
	}

	// Process allow rules
	for _, rule := range config.Allow {
		// Try parsing as a single IP
		if ip := net.ParseIP(rule); ip != nil {
			processor.allowIPs = append(processor.allowIPs, ip)
			continue
		}

		// Try parsing as CIDR
		_, network, err := net.ParseCIDR(rule)
		if err == nil {
			processor.allowCIDRs = append(processor.allowCIDRs, network)
			continue
		}

		// Try parsing as IP range
		ipRange, err := parseIPRange(rule)
		if err == nil {
			processor.allowRanges = append(processor.allowRanges, *ipRange)
			continue
		}

		return nil, fmt.Errorf("invalid IP, CIDR, or range in allow list: %s", rule)
	}

	return processor, nil
}

func (p *IPProcessor) getIP(req *http.Request) net.IP {
	xff := req.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			if ip := net.ParseIP(strings.TrimSpace(ips[0])); ip != nil {
				return ip
			}
		}
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		if ip := net.ParseIP(req.RemoteAddr); ip != nil {
			return ip
		}
		return nil
	}

	return net.ParseIP(host)
}

func (p *IPProcessor) checkIPInDenyList(clientIP net.IP) bool {
	for _, denyIP := range p.denyIPs {
		if denyIP.Equal(clientIP) {
			return true
		}
	}

	for _, denyCIDR := range p.denyCIDRs {
		if denyCIDR.Contains(clientIP) {
			return true
		}
	}

	for _, denyRange := range p.denyRanges {
		if denyRange.IPRangeContains(clientIP) {
			return true
		}
	}

	return false
}

func (p *IPProcessor) checkIPInAllowList(clientIP net.IP) bool {
	if len(p.allowIPs) == 0 && len(p.allowCIDRs) == 0 && len(p.allowRanges) == 0 {
		return false
	}

	for _, allowIP := range p.allowIPs {
		if allowIP.Equal(clientIP) {
			return true
		}
	}

	for _, allowCIDR := range p.allowCIDRs {
		if allowCIDR.Contains(clientIP) {
			return true
		}
	}

	for _, allowRange := range p.allowRanges {
		if allowRange.IPRangeContains(clientIP) {
			return true
		}
	}

	return false
}

func (p *IPProcessor) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := p.getIP(req)
	if clientIP == nil {
		http.Error(rw, "Invalid IP address", http.StatusForbidden)
		return
	}

	var allowed bool

	if p.precedence == "allow" {
		if p.checkIPInAllowList(clientIP) {
			allowed = true
		} else if p.checkIPInDenyList(clientIP) {
			allowed = false
		} else {
			allowed = false
		}
	} else {
		if p.checkIPInDenyList(clientIP) {
			allowed = false
		} else if p.checkIPInAllowList(clientIP) {
			allowed = true
		} else {
			allowed = false
		}
	}

	if !allowed {
		http.Error(rw, "Access denied", http.StatusForbidden)
		return
	}

	p.next.ServeHTTP(rw, req)
}
