"""Explicit fresh-CI and retained metadata profiles; no database lifecycle."""
import hashlib

CURRENT_PROFILE = {"schema": 62, "metadata_tables": 78, "forced_rls_tables": 77}
LOCAL_COLLECTION_PROFILE = {"schema": 61, "metadata_tables": 78, "forced_rls_tables": 77}
AUTHORITY_FENCE_PROFILE = {"schema": 60, "metadata_tables": 78, "forced_rls_tables": 77}
PROCESSING_PROPOSAL_PROFILE = {"schema": 59, "metadata_tables": 78, "forced_rls_tables": 77}
PROCESSING_SCHEDULE_PROFILE = {"schema": 58, "metadata_tables": 77, "forced_rls_tables": 76}
COMPOSED_PROCESSING_PROFILE = {"schema": 57, "metadata_tables": 77, "forced_rls_tables": 76}
PRODUCER_OUTPUT_PROFILE = {"schema": 56, "metadata_tables": 77, "forced_rls_tables": 76}
OUTPUT_REGISTRY_PROFILE = {"schema": 55, "metadata_tables": 76, "forced_rls_tables": 75}
PROCESSING_REVIEW_PROFILE = {"schema": 54, "metadata_tables": 75, "forced_rls_tables": 74}
PROCESSING_PROFILE = {"schema": 53, "metadata_tables": 74, "forced_rls_tables": 73}
SCOPED_PROJECTION_PROFILE = {"schema": 52, "metadata_tables": 73, "forced_rls_tables": 72}
PROJECTION_PROFILE = {"schema": 51, "metadata_tables": 73, "forced_rls_tables": 72}
XLSX_RECORDS_PROFILE = {"schema": 50, "metadata_tables": 71, "forced_rls_tables": 70}
XML_RECORDS_PROFILE = {"schema": 49, "metadata_tables": 71, "forced_rls_tables": 70}
FIXED_WIDTH_PROFILE = {"schema": 48, "metadata_tables": 71, "forced_rls_tables": 70}
JSON_RECORDS_PROFILE = {"schema": 47, "metadata_tables": 71, "forced_rls_tables": 70}
AUDIT_PROFILE = {"schema": 46, "metadata_tables": 71, "forced_rls_tables": 70}
COPY_PROFILE = {"schema": 45, "metadata_tables": 71, "forced_rls_tables": 70}
HISTORY_PROFILE = {"schema": 44, "metadata_tables": 71, "forced_rls_tables": 70}
CLOSURE_PROFILE = {"schema": 43, "metadata_tables": 71, "forced_rls_tables": 70}
RECEIVE_VIEW_PROFILE = {"schema": 42, "metadata_tables": 69, "forced_rls_tables": 68}
PREVIOUS_PROFILE = {"schema": 41, "metadata_tables": 67, "forced_rls_tables": 66}
COLLECTION_FTPS_PROFILE = {"schema": 40, "metadata_tables": 64, "forced_rls_tables": 63}
ENCRYPTION_FTPS_PROFILE = {"schema": 39, "metadata_tables": 64, "forced_rls_tables": 63}
PROGRAM_FTPS_PROFILE = {"schema": 38, "metadata_tables": 64, "forced_rls_tables": 63}
LEGACY_PROFILE = {"schema": 37, "metadata_tables": 64, "forced_rls_tables": 63}
DIRECT_FTPS_PROFILE = {"schema": 36, "metadata_tables": 64, "forced_rls_tables": 63}
RETAINED_PROFILE = {"schema": 35, "metadata_tables": 64, "forced_rls_tables": 63}


def profile(version):
    if type(version) is not int:
        raise ValueError("metadata schema profile differs")
    for value in (CURRENT_PROFILE, LOCAL_COLLECTION_PROFILE, AUTHORITY_FENCE_PROFILE, PROCESSING_PROPOSAL_PROFILE, PROCESSING_SCHEDULE_PROFILE, COMPOSED_PROCESSING_PROFILE, PRODUCER_OUTPUT_PROFILE, OUTPUT_REGISTRY_PROFILE, PROCESSING_REVIEW_PROFILE, PROCESSING_PROFILE, SCOPED_PROJECTION_PROFILE, PROJECTION_PROFILE, XLSX_RECORDS_PROFILE, XML_RECORDS_PROFILE, FIXED_WIDTH_PROFILE, JSON_RECORDS_PROFILE, AUDIT_PROFILE, COPY_PROFILE, HISTORY_PROFILE, CLOSURE_PROFILE, RECEIVE_VIEW_PROFILE, PREVIOUS_PROFILE, COLLECTION_FTPS_PROFILE, ENCRYPTION_FTPS_PROFILE, PROGRAM_FTPS_PROFILE, LEGACY_PROFILE, DIRECT_FTPS_PROFILE, RETAINED_PROFILE):
        if version == value["schema"]:
            return value
    raise ValueError("metadata schema profile differs")


def migration_ledger(root, version):
    profile(version)
    source = root / "internal/store"
    files = [source / "schema.sql"] + sorted(source.glob("[0-9][0-9][0-9]_*.sql"))
    if len(files) != CURRENT_PROFILE["schema"] or any(p.is_symlink() or not p.is_file() for p in files):
        raise ValueError("metadata migration source profile differs")
    return [{"version": i + 1, "digest": hashlib.sha256(p.read_bytes()).hexdigest()}
            for i, p in enumerate(files[:version])]


def require_snapshot(root, snapshot, version):
    expected = profile(version)
    if (not isinstance(snapshot, dict) or snapshot.get("runtime_role_safe") is not True
            or snapshot.get("migration_ledger") != migration_ledger(root, version)
            or type(snapshot.get("forced_rls_tables")) is not int
            or snapshot["forced_rls_tables"] != expected["forced_rls_tables"]
            or not isinstance(snapshot.get("tables"), list)
            or len(snapshot["tables"]) != expected["metadata_tables"]):
        raise ValueError("metadata schema/security profile differs")
