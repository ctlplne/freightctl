package store

import "github.com/ctlplne/freightctl/internal/vpath"

func validateTreeRemoval(command PathCommand) error {
	if !ValidID(command.ExpectedEntryID) || command.ExpectedRevision == nil || *command.ExpectedRevision < 1 || command.Target != "" || command.FileID != "" || command.ExpectedFileID != "" || command.Replace || command.TargetRevision != nil || command.TargetEntryID != "" || command.Mode != nil || command.Modified != nil || len(command.PropertyChanges) != 0 {
		return ErrState
	}
	source, err := vpath.Canonical(command.Path)
	if err != nil || source != command.Path {
		return vpath.ErrPath
	}
	if source == "/" || vpath.ControlPath(source) {
		return ErrForbidden
	}
	return nil
}
