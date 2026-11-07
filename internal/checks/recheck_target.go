package checks

import "github.com/ctlplne/freightctl/internal/store"

// Called only after path,source identity and current modes are authorized.
// Retain the publication precondition in the later held copy's check binding.
func recheckPublicationTarget(path string, parent *store.PathEntry, entry *store.PathEntry) *RecheckTarget {
	target := &RecheckTarget{Command: store.PathCommand{Operation: "publish", Path: path}, ParentID: parent.ID, ParentRevision: parent.Revision}
	if entry != nil {
		revision, mode := entry.Revision, entry.Mode
		target.Command.ExpectedRevision = &revision
		target.Command.ExpectedFileID = entry.FileID
		target.Command.Replace = true
		target.Command.Mode = &mode
		target.EntryID = entry.ID
		target.EntryRevision = revision
	}
	return target
}
