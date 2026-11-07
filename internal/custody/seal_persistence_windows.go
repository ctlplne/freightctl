//go:build windows

package custody

import (
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"unsafe"

	"github.com/ctlplne/freightctl/internal/protectedfs"
	"golang.org/x/sys/windows"
)

var ErrSealPersistence = errors.New("storage cannot establish the required immutable-file flush record")

type sealFileIdentity struct {
	Volume uint64
	ID     [16]byte
}

func sealIdentity(handle windows.Handle) (sealFileIdentity, error) {
	var result sealFileIdentity
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return result, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return result, ErrIntegrity
	}
	err := windows.GetFileInformationByHandleEx(handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&result)), uint32(unsafe.Sizeof(result)))
	return result, err
}

func setSealEA(handle windows.Handle, value []byte) error {
	wire, err := encodeSealEA(value)
	if err != nil {
		return err
	}
	var status windows.IO_STATUS_BLOCK
	err = windows.NtSetEaFile(handle, &status, &wire[0], uint32(len(wire)))
	runtime.KeepAlive(wire)
	if err != nil || status.Status != 0 {
		return errors.Join(ErrSealPersistence, err)
	}
	return nil
}
func querySealEA(handle windows.Handle) ([]byte, error) {
	// FILE_GET_EA_INFORMATION selects exactly one fixed name. Never enumerate
	// arbitrary user EAs or allocate the size advertised by an untrusted file.
	query := make([]byte, 6+len(sealEAName))
	query[4] = byte(len(sealEAName))
	copy(query[5:], sealEAName)
	wire := make([]byte, 8+len(sealEAName)+1+maximumSealRecord+3)
	var status windows.IO_STATUS_BLOCK
	err := windows.NtQueryEaFile(handle, &status, &wire[0], uint32(len(wire)), true, &query[0], uint32(len(query)), nil, true)
	runtime.KeepAlive(query)
	if errors.Is(err, windows.STATUS_NO_EAS_ON_FILE) || errors.Is(err, windows.STATUS_NONEXISTENT_EA_ENTRY) {
		return nil, nil
	}
	if err != nil || status.Status != 0 {
		return nil, errors.Join(ErrSealPersistence, err)
	}
	if status.Information == 0 {
		return nil, nil
	}
	if status.Information > uintptr(len(wire)) {
		return nil, ErrIntegrity
	}
	return decodeSealEA(wire[:status.Information])
}

func persistCreatedSeal(f *os.File, storage, name string, size int64, digest string) error {
	// The first real FlushFileBuffers must succeed before any completion record
	// is written. The original creator still has its existing write/EA rights;
	// no new handle or sealed-file data-write grant is introduced.
	if err := f.Sync(); err != nil {
		return err
	}
	connection, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var operationErr error
	err = connection.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		identity, e := sealIdentity(h)
		if e != nil {
			operationErr = e
			return
		}
		wire, e := encodeSealRecord(sealRecord{Schema: 1, Store: storage, Object: name, Size: size, SHA256: digest, Volume: identity.Volume, FileID: hex.EncodeToString(identity.ID[:])})
		if e != nil {
			operationErr = e
			return
		}
		operationErr = setSealEA(h, wire)
	})
	if err = errors.Join(err, operationErr); err != nil {
		return err
	}
	// Persist the attached completion metadata too before acknowledging staging.
	if err = f.Sync(); err != nil {
		return err
	}
	complete, err := checkSealPersistence(f, storage, name, size, digest)
	if err != nil || !complete {
		return errors.Join(ErrSealPersistence, err)
	}
	return nil
}

func checkSealPersistence(f *os.File, storage, name string, size int64, digest string) (bool, error) {
	state, err := protectedfs.Protection(f)
	if err != nil || state != protectedfs.PrivateSealed {
		return false, errors.Join(ErrIntegrity, err)
	}
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if size < 0 {
		size = info.Size() // Metadata observation only;no byte-verification claim.
	}
	if info.Size() != size {
		return false, ErrIntegrity
	}
	connection, err := f.SyscallConn()
	if err != nil {
		return false, err
	}
	complete := false
	var operationErr error
	err = connection.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		identity, e := sealIdentity(h)
		if e != nil {
			operationErr = e
			return
		}
		wire, e := querySealEA(h)
		if e != nil || wire == nil {
			operationErr = e
			return
		}
		operationErr = validateSealRecord(wire, sealRecord{Schema: 1, Store: storage, Object: name, Size: size, SHA256: digest, Volume: identity.Volume, FileID: hex.EncodeToString(identity.ID[:])})
		complete = operationErr == nil
	})
	return complete, errors.Join(err, operationErr)
}

func recoverSealPersistence(f *os.File, storage, name string, size int64, digest string) error {
	// A read-only handle cannot FlushFileBuffers. Require the original real
	// data-flush completion record on this exact native object instead. The
	// caller still hashes every byte and syncs the held directory after this.
	complete, err := checkSealPersistence(f, storage, name, size, digest)
	if err != nil || !complete {
		return errors.Join(ErrIntegrity, err)
	}
	return nil
}
