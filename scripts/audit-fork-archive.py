"""Reject private data and unsafe entries before publishing the fork archive."""
import re
import sys
import tarfile
from pathlib import PurePosixPath

with tarfile.open(sys.argv[1], "r:gz") as archive:
    entries = archive.getmembers()
    roots = {PurePosixPath(entry.name).parts[0] for entry in entries}
    assert len(roots) == 1, "Expected one archive root"
    root = roots.pop()
    required = {f"{root}/t3", f"{root}/client/index.html",
                f"{root}/resource-monitor/linux-x64/t3-resource-monitor"}
    names = {entry.name for entry in entries}
    assert required <= names, "Archive missing runtime files"
    assert any(name.endswith(".node") for name in names), "Missing native modules"
    forbidden = {".git", ".t3", ".env", ".npmrc", "AUDIT.md", "secrets", "credentials.json", "settings.json"}
    patterns = [rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
                rb"gh[pousr]_[A-Za-z0-9]{30,}", rb"github_pat_[A-Za-z0-9_]{40,}",
                rb"ya29\.[A-Za-z0-9_-]{30,}", rb"1//[A-Za-z0-9_-]{40,}"]
    for entry in entries:
        path = PurePosixPath(entry.name)
        assert not path.is_absolute() and ".." not in path.parts, "Unsafe archive path"
        assert entry.isfile() or entry.isdir(), "Links and special files are forbidden"
        assert not forbidden.intersection(path.parts), "Private data filename"
        assert not entry.name.endswith((".sqlite", ".sqlite-wal", ".sqlite-shm", ".db", ".pem", ".p12", ".p8")), "Private data extension"
        if entry.isfile():
            data = archive.extractfile(entry).read()
            assert not any(re.search(pattern, data) for pattern in patterns), "Credential pattern found"
    print(f"Archive audit passed: {len(entries)} entries; runtime files present; no private data or credential patterns found")
