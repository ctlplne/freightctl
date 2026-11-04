//go:build !unix

package main

import "net"

func drainPending(*net.TCPListener, func() error) error { return errFixture }
