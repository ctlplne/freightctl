package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

type setupPlan struct {
	Request    store.SetupRequest `json:"request"`
	Credential string             `json:"credential_file"`
	Storage    string             `json:"storage_root"`
}

func privateParent(path string) error {
	st, err := os.Stat(filepath.Dir(path))
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("setup reference parent must already be a private mode-0700 directory")
	}
	return nil
}
func setupToken(path string, create bool) (*secure.Secret, error) {
	if create {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			if err = secure.WriteToken(path); err != nil {
				return nil, err
			}
		}
	}
	s, err := secure.ReadSecret(path, 64)
	if err != nil {
		return nil, err
	}
	valid := len(s.Bytes) == 64
	for _, b := range s.Bytes {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			valid = false
		}
	}
	if !valid {
		s.Close()
		return nil, errors.New("setup credential must be a protected 64-character lowercase hexadecimal token")
	}
	return s, nil
}

func prepareSetup(output, tokenPath, storagePath, tenantLabel, partnerLabel, adminLabel string) error {
	var err error
	output, err = filepath.Abs(output)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return errors.New("setup plan already exists or cannot be inspected; preserve it and run setup --request-file with that exact plan")
	}
	tokenPath, err = filepath.Abs(tokenPath)
	if err != nil {
		return err
	}
	storagePath, err = filepath.Abs(storagePath)
	if err != nil {
		return err
	}
	for _, path := range []string{output, tokenPath} {
		if err = privateParent(path); err != nil {
			return err
		}
	}
	// Validate human input before creating any credential or storage identity.
	request := store.SetupRequest{SchemaVersion: 1, RequestKey: secure.NewID(), Tenant: secure.NewID(), Partner: secure.NewID(), Admin: secure.NewID(), TenantLabel: tenantLabel, PartnerLabel: partnerLabel, AdminLabel: adminLabel, Credential: secure.Digest(nil), Storage: secure.NewID(), Permissions: slices.Clone(store.DefaultPermissions)}
	if _, err = store.NormalizeSetup(request); err != nil {
		return err
	}
	disk, err := custody.Open(storagePath)
	if err != nil {
		return err
	}
	defer disk.Close()
	token, err := setupToken(tokenPath, true)
	if err != nil {
		return err
	}
	defer token.Close()
	// Persist the directory entry too before a database commit can refer to it.
	directory, err := os.Open(filepath.Dir(tokenPath))
	if err != nil {
		return err
	}
	err = directory.Sync()
	directory.Close()
	if err != nil {
		return err
	}
	request.Credential, request.Storage = secure.Digest(token.Bytes), disk.Identity()
	request, err = store.NormalizeSetup(request)
	if err != nil {
		return err
	}
	return writeArtifact(output, setupPlan{Request: request, Credential: tokenPath, Storage: storagePath})
}

func applySetup(ctx context.Context, adminPath, planPath string) (*store.SetupResult, error) {
	data, err := secure.ReadSecret(planPath, 16<<10)
	if err != nil {
		return nil, err
	}
	defer data.Close()
	decoder := json.NewDecoder(bytes.NewReader(data.Bytes))
	decoder.DisallowUnknownFields()
	var plan setupPlan
	if err = decoder.Decode(&plan); err != nil {
		return nil, store.ErrSetupInput
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || !filepath.IsAbs(plan.Credential) || !filepath.IsAbs(plan.Storage) {
		return nil, store.ErrSetupInput
	}
	if _, err = store.NormalizeSetup(plan.Request); err != nil {
		return nil, err
	}
	token, err := setupToken(plan.Credential, false)
	if err != nil {
		return nil, err
	}
	defer token.Close()
	if secure.Digest(token.Bytes) != plan.Request.Credential {
		return nil, errors.New("setup credential changed; preserve the original plan and credential")
	}
	disk, err := custody.OpenExisting(plan.Storage)
	if err != nil {
		return nil, err
	}
	defer disk.Close()
	if disk.Identity() != plan.Request.Storage {
		return nil, errors.New("setup storage identity changed; restore the reviewed storage reference")
	}
	return store.InitializeInstallation(ctx, adminPath, plan.Request)
}
