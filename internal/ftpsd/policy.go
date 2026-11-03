package ftpsd

import (
	"net"
	"strconv"
	"strings"

	ftp "github.com/fclairamb/ftpserverlib"
)

// Command policy only refuses. Authentication, current authority and file
// permissions still belong to the normal engine and custody operations.
func (d *sessionDriver) BeforeCommand(cc ftp.ClientContext, command, parameter string) *ftp.AnswerCommand {
	d.mu.Lock()
	defer d.mu.Unlock()
	refuse := func(code int, message string) *ftp.AnswerCommand {
		return &ftp.AnswerCommand{Code: code, Message: message}
	}
	if d.closed || d.ctx.Err() != nil {
		return refuse(421, "Session closed")
	}
	if !cc.HasTLSForControl() && command != "AUTH" && command != "FEAT" && command != "QUIT" && command != "NOOP" {
		return refuse(534, "TLS is required before authentication or file commands")
	}
	switch command {
	case "AUTH":
		if cc.HasTLSForControl() || !(strings.EqualFold(parameter, "TLS") || strings.EqualFold(parameter, "TLS-C")) {
			return refuse(504, "A fresh AUTH TLS is required")
		}
	case "PBSZ":
		if parameter != "0" {
			return refuse(501, "PBSZ must be zero")
		}
		d.pbsz = true
	case "PROT":
		if !d.pbsz {
			return refuse(503, "PBSZ 0 must precede PROT P")
		}
		if !strings.EqualFold(parameter, "P") {
			return refuse(534, "Encrypted data is required")
		}
		d.prot = true
	case "PORT", "EPRT":
		if !d.server.options.EnableActive || !safeActiveDestination(command, parameter, cc.RemoteAddr()) {
			return refuse(501, "Active data must use the control peer's numeric address and an unprivileged port")
		}
	case "STOR", "APPE", "RETR", "LIST", "NLST", "MLSD":
		if !d.pbsz || !d.prot {
			return refuse(534, "PBSZ 0 and PROT P are required before transfer")
		}
	}
	return nil
}

func safeActiveDestination(command, parameter string, remote net.Addr) bool {
	peer, ok := remote.(*net.TCPAddr)
	if !ok || peer == nil || peer.IP == nil {
		return false
	}
	var ip net.IP
	port := 0
	if command == "PORT" {
		parts := strings.Split(parameter, ",")
		if len(parts) != 6 {
			return false
		}
		var values [6]int
		for i, value := range parts {
			if value == "" || len(value) > 3 {
				return false
			}
			for _, c := range value {
				if c < '0' || c > '9' {
					return false
				}
			}
			n, err := strconv.Atoi(value)
			if err != nil || n > 255 || (i < 4 && value != strconv.Itoa(n)) {
				return false
			}
			values[i] = n
		}
		ip = net.IPv4(byte(values[0]), byte(values[1]), byte(values[2]), byte(values[3]))
		port = values[4]*256 + values[5]
	} else if command == "EPRT" {
		if len(parameter) < 5 || len(parameter) > 80 {
			return false
		}
		delim := parameter[0]
		if delim < 33 || delim > 126 {
			return false
		}
		parts := strings.Split(parameter, string(delim))
		if len(parts) != 5 || parts[0] != "" || parts[4] != "" || (parts[1] != "1" && parts[1] != "2") {
			return false
		}
		ip = net.ParseIP(parts[2])
		if ip == nil || (parts[1] == "1" && ip.To4() == nil) || (parts[1] == "2" && ip.To4() != nil) {
			return false
		}
		if len(parts[3]) == 0 || len(parts[3]) > 5 {
			return false
		}
		for _, c := range parts[3] {
			if c < '0' || c > '9' {
				return false
			}
		}
		var err error
		port, err = strconv.Atoi(parts[3])
		if err != nil {
			return false
		}
	} else {
		return false
	}
	return ip.Equal(peer.IP) && port >= 1024 && port <= 65535
}
