package ftpserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func (c *clientHandler) handlePORT(param string) error {
	command := c.GetLastCommand()

	if c.server.settings.DisableActiveMode {
		c.writeMessage(StatusServiceNotAvailable, fmt.Sprintf("%v command is disabled", command))

		return nil
	}

	var err error
	var raddr *net.TCPAddr

	if command == cmdEPRT {
		raddr, err = parseEPRTAddr(param)
	} else { // PORT
		raddr, err = parsePORTAddr(param)
	}

	if err != nil {
		c.writeMessage(StatusSyntaxErrorParameters, fmt.Sprintf("Problem parsing %s: %v", param, err))

		return nil
	}

	err = c.checkDataConnectionRequirement(raddr.IP, DataChannelActive)
	if err != nil {
		// we don't want to expose the full error to the client, we just log it
		c.logger.Warn("Could not validate active data connection requirement", "err", err)
		c.writeMessage(StatusSyntaxErrorParameters, "Your request does not meet "+
			"the configured security requirements")

		return nil
	}

	var tlsConfig *tls.Config

	if c.HasTLSForTransfers() || c.server.settings.TLSRequired == ImplicitEncryption {
		tlsConfig, err = c.server.driver.GetTLSConfig()
		if err != nil {
			c.writeMessage(StatusServiceNotAvailable, fmt.Sprintf("Cannot get a TLS config for active connection: %v", err))

			return nil
		}
	}

	var laddr net.IP

	if resolver := c.server.settings.ActiveTransferLocalIPResolver; resolver != nil {
		laddr = resolver(c)
	}

	c.transferMu.Lock()

	// Release any previous handler (e.g. a passive listener from an earlier PASV), as handlePASV does.
	if c.transfer != nil {
		c.transfer.Close() //nolint:errcheck,gosec
	}

	c.transfer = &activeTransferHandler{
		raddr:     raddr,
		laddr:     laddr,
		settings:  c.server.settings,
		tlsConfig: tlsConfig,
		driver:    c.server.driver,
	}

	c.transferMu.Unlock()
	c.setLastDataChannel(DataChannelActive)

	c.writeMessage(StatusOK, command+" command successful")

	return nil
}

// activeTransferHandler implements the transferHandler interface
var _ transferHandler = (*activeTransferHandler)(nil)

// Active connection
type activeTransferHandler struct {
	raddr     *net.TCPAddr // Remote address of the client
	laddr     net.IP       // Local address to dial from, nil lets the operating system choose
	conn      net.Conn     // Connection used to connect to him
	settings  *Settings    // Settings
	tlsConfig *tls.Config  // not nil if the active connection requires TLS
	driver    MainDriver
	info      string // transfer info
}

func (a *activeTransferHandler) GetInfo() string {
	return a.info
}

func (a *activeTransferHandler) SetInfo(info string) {
	a.info = info
}

func (a *activeTransferHandler) Open() (net.Conn, error) {
	timeout := time.Duration(time.Second.Nanoseconds() * int64(a.settings.ConnectionTimeout))
	dialer := &net.Dialer{Timeout: timeout}

	if !a.settings.ActiveTransferPortNon20 {
		// Several transfers may dial from port 20 at once, so the socket must be reusable
		dialer.LocalAddr = &net.TCPAddr{IP: a.laddr, Port: 20}
		dialer.Control = Control
	} else if a.laddr != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: a.laddr}
	}

	conn, err := dialer.Dial("tcp", a.raddr.String())
	if err != nil {
		return nil, newNetworkError("could not establish active connection", err)
	}
	if wrapper, ok := a.driver.(MainDriverExtensionActiveWrapper); ok {
		wrapped, wrapErr := wrapper.WrapActiveConnection(conn)
		if wrapErr != nil {
			_ = conn.Close()
			return nil, newNetworkError("active connection refused", wrapErr)
		}
		conn = wrapped
	}

	if a.tlsConfig != nil {
		conn = tls.Server(conn, a.tlsConfig)
	}

	// keep connection as it will be closed by Close()
	a.conn = conn

	return a.conn, nil
}

// Close closes only if connection is established
func (a *activeTransferHandler) Close() error {
	if a.conn != nil {
		if err := a.conn.Close(); err != nil {
			return newNetworkError("could not close active connection", err)
		}
	}

	return nil
}

var remoteAddrRegex = regexp.MustCompile(`^([0-9]{1,3},){5}[0-9]{1,3}$`)

// ErrRemoteAddrFormat is returned when the remote address has a bad format
var ErrRemoteAddrFormat = errors.New("remote address has a bad format")

// parsePORTAddr parses remote address of the client from param. This address
// is used for establishing a connection with the client.
//
// Param Format: 192,168,150,80,14,178
// Host: 192.168.150.80
// Port: (14 * 256) + 148
func parsePORTAddr(param string) (*net.TCPAddr, error) {
	if !remoteAddrRegex.MatchString(param) {
		return nil, ErrRemoteAddrFormat
	}
	parts := strings.Split(param, ",")
	var values [6]int
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return nil, ErrRemoteAddrFormat
		}
		values[i] = n
	}
	port := values[4]*256 + values[5]
	if port < 1 {
		return nil, ErrRemoteAddrFormat
	}
	return &net.TCPAddr{IP: net.IPv4(byte(values[0]), byte(values[1]), byte(values[2]), byte(values[3])), Port: port}, nil
}

// parseEPRTAddr accepts RFC2428's delimiter and numeric address-family binding.
// Constructing TCPAddr directly prevents numeric input from becoming DNS work.
func parseEPRTAddr(param string) (*net.TCPAddr, error) {
	if len(param) < 5 || len(param) > 80 || param[0] < 33 || param[0] > 126 {
		return nil, ErrRemoteAddrFormat
	}
	parts := strings.Split(param, string(param[0]))
	if len(parts) != 5 || parts[0] != "" || parts[4] != "" {
		return nil, ErrRemoteAddrFormat
	}
	ip := net.ParseIP(parts[2])
	if ip == nil || (parts[1] != "1" && parts[1] != "2") || (parts[1] == "1" && ip.To4() == nil) || (parts[1] == "2" && ip.To4() != nil) {
		return nil, ErrRemoteAddrFormat
	}
	if len(parts[3]) < 1 || len(parts[3]) > 5 {
		return nil, ErrRemoteAddrFormat
	}
	for _, c := range parts[3] {
		if c < '0' || c > '9' {
			return nil, ErrRemoteAddrFormat
		}
	}
	port, err := strconv.Atoi(parts[3])
	if err != nil || port < 1 || port > 65535 {
		return nil, ErrRemoteAddrFormat
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}
