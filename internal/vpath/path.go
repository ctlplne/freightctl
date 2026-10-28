// Package vpath handles virtual names. Its output must never be a host storage path.
package vpath

import (
	"errors"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var ErrPath = errors.New("invalid virtual path")

func Canonical(value string) (string, error) {
	if !utf8.ValidString(value) || len(value) == 0 || len(value) > 1024 || value[0] != '/' {
		return "", ErrPath
	}
	value = norm.NFC.String(value)
	if len(value) > 1024 {
		return "", ErrPath
	}
	if value == "/" {
		return value, nil
	}
	for _, part := range strings.Split(value[1:], "/") {
		if part == "" || part == "." || part == ".." || len(part) > 255 || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return "", ErrPath
		}
		for _, c := range part {
			if unicode.IsControl(c) || c == '\\' || c == ':' {
				return "", ErrPath
			}
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
			return "", ErrPath
		}
	}
	return value, nil
}

func Within(root, value string) bool {
	return root == "/" && strings.HasPrefix(value, "/") || value == root || strings.HasPrefix(value, root+"/")
}
func Resolve(root, virtual string) (string, error) {
	r, err := Canonical(root)
	if err != nil {
		return "", err
	}
	v, err := Canonical(virtual)
	if err != nil {
		return "", err
	}
	if r == "/" {
		return v, nil
	}
	if v == "/" {
		return r, nil
	}
	return Canonical(r + v)
}
func Relative(root, actual string) (string, error) {
	if !Within(root, actual) {
		return "", ErrPath
	}
	if root == "/" {
		return actual, nil
	}
	if actual == root {
		return "/", nil
	}
	return strings.TrimPrefix(actual, root), nil
}
func Parent(value string) string { return path.Dir(value) }
