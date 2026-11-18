package migration

import "fmt"

type SFTPGoAccessRecord struct {
	Source       string                   `json:"source"`
	SourceState  string                   `json:"source_state,omitempty"`
	SourceScope  string                   `json:"source_scope,omitempty"`
	Disposition  string                   `json:"disposition"`
	Reason       string                   `json:"reason"`
	Dependencies []SFTPGoAccessDependency `json:"dependencies"`
}

type SFTPGoAccessDependency struct {
	Source      string `json:"source"`
	Target      string `json:"target,omitempty"`
	Kind        string `json:"kind"`
	Membership  string `json:"membership,omitempty"`
	Disposition string `json:"disposition"`
	Reason      string `json:"reason"`
}

type sftpgoAccessDump struct {
	Folders []sftpgoNamed   `json:"folders"`
	Roles   []sftpgoNamed   `json:"roles"`
	Groups  []sftpgoGroup   `json:"groups"`
	Users   []sftpgoAccount `json:"users"`
	Admins  []sftpgoAccount `json:"admins"`
	APIKeys []sftpgoAPIKey  `json:"api_keys"`
	Shares  []sftpgoShare   `json:"shares"`
}

type sftpgoNamed struct {
	Name string `json:"name"`
}

type sftpgoGroup struct {
	sftpgoNamed
	Folders []sftpgoNamed `json:"virtual_folders"`
}

type sftpgoAccount struct {
	Username string        `json:"username"`
	Status   *int          `json:"status"`
	Role     string        `json:"role"`
	Folders  []sftpgoNamed `json:"virtual_folders"`
	Groups   []struct {
		sftpgoNamed
		Type int `json:"type"`
	} `json:"groups"`
}

type sftpgoAPIKey struct {
	Scope int    `json:"scope"`
	User  string `json:"user"`
	Admin string `json:"admin"`
}

type sftpgoShare struct {
	Scope    int    `json:"scope"`
	Username string `json:"username"`
}

type sourceNames map[string]string

func (index sourceNames) add(name, source string) {
	if _, duplicate := index[name]; duplicate || name == "" {
		index[name] = ""
		return
	}
	index[name] = source
}

func planSFTPGoAccess(dump sftpgoAccessDump) []SFTPGoAccessRecord {
	records := make([]SFTPGoAccessRecord, 0, len(dump.Folders)+len(dump.Roles)+len(dump.Groups)+len(dump.Users)+len(dump.Admins)+len(dump.APIKeys)+len(dump.Shares))
	folders := make(sourceNames, len(dump.Folders))
	roles := make(sourceNames, len(dump.Roles))
	groups := make(sourceNames, len(dump.Groups))
	for _, section := range []struct {
		path    string
		reason  string
		entries []sftpgoNamed
		index   sourceNames
	}{
		{"/folders", "review_storage_and_mount_boundaries", dump.Folders, folders},
		{"/roles", "review_role_scope", dump.Roles, roles},
	} {
		for i, entry := range section.entries {
			section.index.add(entry.Name, fmt.Sprintf("%s/%d", section.path, i))
		}
		for i, entry := range section.entries {
			path := fmt.Sprintf("%s/%d", section.path, i)
			row := accessRecord(path, section.index[entry.Name] != "", section.reason)
			records = append(records, row)
		}
	}
	for i, group := range dump.Groups {
		groups.add(group.Name, fmt.Sprintf("/groups/%d", i))
	}
	for i, group := range dump.Groups {
		row := accessRecord(fmt.Sprintf("/groups/%d", i), groups[group.Name] != "", "review_group_inheritance")
		row.addFolders(group.Folders, folders)
		records = append(records, row)
	}
	users, admins := make(sourceNames, len(dump.Users)), make(sourceNames, len(dump.Admins))
	for _, section := range []struct {
		path     string
		accounts []sftpgoAccount
		names    sourceNames
	}{
		{"/users", dump.Users, users},
		{"/admins", dump.Admins, admins},
	} {
		for i, account := range section.accounts {
			section.names.add(account.Username, fmt.Sprintf("%s/%d", section.path, i))
		}
		for i, account := range section.accounts {
			path := fmt.Sprintf("%s/%d", section.path, i)
			row := accessRecord(path, section.names[account.Username] != "", "review_account_scope_and_reenroll_credentials")
			row.SourceState = sftpgoStatus(account.Status)
			if row.SourceState == "unknown" && row.Disposition == "needs_input" {
				row.Disposition, row.Reason = "blocked", "missing_or_invalid_account_state"
			}
			if account.Role != "" {
				row.addDependency(path+"/role", roles[account.Role], "role", "")
			}
			for j, group := range account.Groups {
				kind, membership := "managed_group", ""
				if section.path == "/users" {
					kind = "group_membership"
					switch group.Type {
					case 1:
						membership = "primary"
					case 2:
						membership = "secondary"
					case 3:
						membership = "membership_only"
					}
				}
				row.addDependency(fmt.Sprintf("%s/groups/%d", path, j), groups[group.Name], kind, membership)
			}
			row.addFolders(account.Folders, folders)
			records = append(records, row)
		}
	}
	for i, key := range dump.APIKeys {
		records = append(records, planSFTPGoAPIKey(i, key, users, admins))
	}
	for i, share := range dump.Shares {
		records = append(records, planSFTPGoShare(i, share, users))
	}
	return records
}

func accessRecord(source string, identityOK bool, reason string) SFTPGoAccessRecord {
	row := SFTPGoAccessRecord{
		Source: source, Disposition: "needs_input", Reason: reason, Dependencies: []SFTPGoAccessDependency{},
	}
	if !identityOK {
		row.Disposition, row.Reason = "blocked", "missing_or_duplicate_source_identity"
	}
	return row
}

func planSFTPGoAPIKey(i int, key sftpgoAPIKey, users, admins sourceNames) SFTPGoAccessRecord {
	row := accessRecord(fmt.Sprintf("/api_keys/%d", i), true, "review_scope_and_issue_new_credential")
	var field, owner, conflictingOwner string
	var names sourceNames
	switch key.Scope {
	case 1:
		field, owner, conflictingOwner, names = "admin", key.Admin, key.User, admins
	case 2:
		field, owner, conflictingOwner, names = "user", key.User, key.Admin, users
	default:
		row.Disposition, row.Reason = "blocked", "unknown_api_key_scope"
		return row
	}
	row.SourceScope = field
	switch {
	case conflictingOwner != "":
		row.Disposition, row.Reason = "blocked", "api_key_owner_conflicts_with_scope"
	case owner == "":
		row.SourceScope = "all_" + field + "s"
		row.Disposition, row.Reason = "unsupported", "unbound_api_key_requires_explicit_account_mapping"
	default:
		row.addDependency(row.Source+"/"+field, names[owner], "api_key_owner", "")
	}
	return row
}

func planSFTPGoShare(i int, share sftpgoShare, users sourceNames) SFTPGoAccessRecord {
	row := accessRecord(fmt.Sprintf("/shares/%d", i), true, "review_share_paths_expiry_and_reissue")
	switch share.Scope {
	case 1:
		row.SourceScope = "read"
	case 2:
		row.SourceScope = "write"
	case 3:
		row.SourceScope = "read_write"
	default:
		row.Disposition, row.Reason = "blocked", "unknown_share_scope"
	}
	row.addDependency(row.Source+"/username", users[share.Username], "share_owner", "")
	return row
}

func (record *SFTPGoAccessRecord) addFolders(mappings []sftpgoNamed, folders sourceNames) {
	for i, folder := range mappings {
		record.addDependency(fmt.Sprintf("%s/virtual_folders/%d", record.Source, i), folders[folder.Name], "virtual_folder", "")
	}
}

func (record *SFTPGoAccessRecord) addDependency(source, target, kind, membership string) {
	edge := SFTPGoAccessDependency{
		Source: source, Target: target, Kind: kind, Membership: membership,
		Disposition: "needs_input", Reason: "review_resulting_access_boundary",
	}
	switch {
	case target == "":
		edge.Disposition, edge.Reason = "blocked", "source_reference_unresolved"
	case kind == "group_membership" && membership == "":
		edge.Disposition, edge.Reason = "blocked", "unknown_group_membership_type"
	}
	if edge.Disposition == "blocked" && record.Disposition != "blocked" {
		record.Disposition, record.Reason = "blocked", "unresolved_access_dependency"
	}
	record.Dependencies = append(record.Dependencies, edge)
}
