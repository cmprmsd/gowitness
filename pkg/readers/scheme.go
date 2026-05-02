package readers

import "strings"

// SchemeForPort returns "vnc", "rdp", or "" based on a port number alone.
// Used by readers (cidr) that don't have service-name information.
func SchemeForPort(port int) string {
	switch {
	case port == 3389:
		return "rdp"
	case port >= 5900 && port <= 5910:
		return "vnc"
	}
	return ""
}

// SchemeForService returns "vnc", "rdp", or "" based on a service name as
// reported by nmap or nessus. Match is case-insensitive and tolerates the
// most common labels each tool emits.
func SchemeForService(service string) string {
	s := strings.ToLower(strings.TrimSpace(service))
	switch s {
	case "vnc", "vnc-1", "vnc-2", "rfb":
		return "vnc"
	case "ms-wbt-server", "ms-rdp", "rdp", "ms-wbt", "msrdp":
		return "rdp"
	}
	if strings.Contains(s, "rdp") || strings.Contains(s, "wbt-server") {
		return "rdp"
	}
	if strings.HasPrefix(s, "vnc") || strings.Contains(s, "rfb") {
		return "vnc"
	}
	return ""
}

// SchemeFor combines service-name and port-based detection. Service name
// takes precedence; port is the fallback when the service name is empty
// or doesn't recognise a non-web protocol.
func SchemeFor(service string, port int) string {
	if s := SchemeForService(service); s != "" {
		return s
	}
	return SchemeForPort(port)
}
