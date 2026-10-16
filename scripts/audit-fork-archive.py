"""Reject private data and unsafe entries before publishing the fork archive."""
import base64
import binascii
import re
import sys
import tarfile
from pathlib import PurePosixPath

# Scan the bytes represented by embedded assets, rather than random base64 text.
DATA_URI = re.compile(rb"data:[^\s\"'`<>;,]+(?:;[^\s\"'`<>,;]+)*;base64,([A-Za-z0-9+/=]+)")


def credential_payloads(data):
    decoded = []

    def replace_asset(match):
        try:
            payload = base64.b64decode(match.group(1), validate=True)
        except binascii.Error:
            return match.group(0)
        decoded.append(payload)
        return b""

    text = DATA_URI.sub(replace_asset, data)
    yield from decoded
    yield text.replace(b"\\n", b"\n")


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
    # Node/OpenSSL embeds PEM delimiter strings without key material.
    patterns = [rb"-----BEGIN (?P<key_kind>(?:RSA |EC |OPENSSH )?PRIVATE KEY)-----[ \t]*\r?\n[A-Za-z0-9+/=\r\n]{40,}-----END (?P=key_kind)-----",
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
            for scan_data in credential_payloads(data):
                for index, pattern in enumerate(patterns):
                    assert not re.search(pattern, scan_data), f"Credential pattern {index} found in {entry.name}"
    print(f"Archive audit passed: {len(entries)} entries; runtime files present; no private data or credential patterns found")
