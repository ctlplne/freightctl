//go:build unix

package main

import (
	"errors"
	"net"
	"syscall"
)

func drainPending(listener *net.TCPListener, accepted func() error) error {
	raw, err := listener.SyscallConn()
	if err != nil {
		return errFixture
	}
	var failed error
	err = raw.Control(func(fd uintptr) {
		failed = drainAccepted(func() (int, error) {
			peer, _, err := syscall.Accept(int(fd))
			return peer, err
		}, syscall.Close, accepted)
	})
	if err != nil || failed != nil {
		return errFixture
	}
	return nil
}

func drainAccepted(accept func() (int, error), close func(int) error, record func() error) error {
	for i := 0; i < 17; i++ {
		peer, err := accept()
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return nil
		}
		if err != nil || peer < 0 {
			return errFixture
		}
		if close(peer) != nil || record() != nil {
			return errFixture
		}
	}
	return errFixture
}
