package namespaceprops

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"strings"
)

const Namespace = "urn:freightctl:namespace"
const MaxSnapshotBytes = 32 << 10

var ErrProtected = errors.New("protected namespace property")
var ErrLimit = errors.New("namespace property capacity exceeded")

// A key names an expanded XML name,independent of its prefix spelling.
func Key(name xml.Name) string { return "{" + name.Space + "}" + name.Local }

func protected(name xml.Name) bool {
	return name.Space == "DAV:" || name.Space == "urn:freightctl" || strings.HasPrefix(name.Space, "urn:freightctl:")
}

// Validate never trusts persisted XML merely because it came from PostgreSQL.
// The complete snapshot has a finite size and no protected live properties.
func Validate(properties map[string]string) error {
	if len(properties) > MaxChanges {
		return ErrLimit
	}
	for key, value := range properties {
		name, err := Inspect(value, false)
		if err != nil || key != Key(name) {
			return ErrXML
		}
		if protected(name) {
			return ErrProtected
		}
	}
	encoded, err := json.Marshal(properties)
	// PostgreSQL jsonb text inserts at most two separator spaces per member.
	if err != nil || len(encoded)+2*len(properties) > MaxSnapshotBytes {
		return ErrLimit
	}
	return nil
}

func ValidateChanges(changes []Change) error {
	if len(changes) == 0 || len(changes) > MaxChanges {
		return ErrLimit
	}
	encoded, err := json.Marshal(changes)
	if err != nil || len(encoded) > MaxIntentBytes {
		return ErrLimit
	}
	for _, change := range changes {
		if change.Operation != "set" && change.Operation != "remove" {
			return ErrXML
		}
		name, err := Inspect(change.Property, change.Operation == "remove")
		if err != nil {
			return err
		}
		if protected(name) {
			return ErrProtected
		}
	}
	return nil
}

// Apply computes a private copy. An error never returns a partially changed
// snapshot,and a removed absent name has the ordinary no-op meaning.
func Apply(previous map[string]string, changes []Change) (map[string]string, error) {
	if err := Validate(previous); err != nil {
		return nil, err
	}
	if err := ValidateChanges(changes); err != nil {
		return nil, err
	}
	next := clone(previous)
	for _, change := range changes {
		name, _ := Inspect(change.Property, change.Operation == "remove")
		if change.Operation == "remove" {
			delete(next, Key(name))
		} else {
			next[Key(name)] = change.Property
		}
	}
	if err := Validate(next); err != nil {
		return nil, err
	}
	return next, nil
}
