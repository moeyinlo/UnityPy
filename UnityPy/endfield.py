"""Read Endfield Bundle/InitBundle indexes without loading the entire VFS.

Only bundle groups are accepted; tables, Lua, and other game data are excluded.
"""

import base64
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

from .helpers.EndfieldBundle import Cursor

PC_KEY = base64.b64decode("6VsxesT4KFadI6hr8nHctT6Eb6dckk1nHbqOOPTKUuE=")
ANDROID_KEY = base64.b64decode("eU1cu+MYQiaYdVherRzV86pv/N/lIU/9gIk+5n5Vj4Y=")
BUNDLE_GROUPS = ("0CE8FA57", "7064D8E2")
PATCH_TAG = 0x00209C855B11B951


def _decrypt(data, key, nonce):
    if len(key) != 32:
        raise ValueError("Endfield ChaCha20 key must have 32 bytes")
    try:
        from Crypto.Cipher import ChaCha20
    except ImportError as exc:
        raise ImportError("Install UnityPy[endfield] to read Endfield VFS indexes") from exc
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cipher.seek(64)  # IETF ChaCha20 starts at counter 1, not PyCryptodome's 0.
    return cipher.decrypt(data)


@dataclass(frozen=True)
class EndfieldEntry:
    name: str
    chunk: Path
    offset: int
    size: int
    encrypted: bool
    iv_seed: int
    version: int
    md5: bytes
    patch: bool
    group: str


class EndfieldVFS:
    """Index a VFS root, bundle group, .blc, or .chk; read bundles on demand.

    A .chk requires its sibling group .blc. ``entries`` is keyed by bundle name;
    patch entries override base entries, then Bundle overrides InitBundle.
    """

    def __init__(self, path, *, key=PC_KEY):
        self.path = Path(path).expanduser().resolve()
        self.key = bytes(key)
        if len(self.key) != 32:
            raise ValueError("Endfield ChaCha20 key must have 32 bytes")
        self.entries = {}
        path = self.path
        selected_chunk = None
        if path.is_file():
            if path.suffix.lower() == ".chk":
                selected_chunk = path
                indexes = [path.parent / (path.parent.name + ".blc")]
            elif path.suffix.lower() == ".blc":
                indexes = [path]
            else:
                raise ValueError("Expected Endfield .blc or .chk")
        else:
            if (path / "VFS").is_dir():
                path /= "VFS"
            if path.name.upper() in BUNDLE_GROUPS:
                indexes = [path / (path.name + ".blc")]
            else:
                indexes = [path / group / (group + ".blc") for group in BUNDLE_GROUPS]
                indexes = [p for p in indexes if p.is_file()]
        if not indexes:
            raise FileNotFoundError("No Endfield bundle indexes found in %s" % self.path)
        for index in indexes:
            self._index(index, selected_chunk)

    @staticmethod
    def recognizes(path):
        path = Path(path)
        if path.is_file():
            return path.suffix.lower() in (".blc", ".chk") and path.parent.name.upper() in BUNDLE_GROUPS
        root = path / "VFS" if (path / "VFS").is_dir() else path
        return (root.name.upper() in BUNDLE_GROUPS and (root / (root.name + ".blc")).is_file()) or any(
            (root / group / (group + ".blc")).is_file() for group in BUNDLE_GROUPS
        )

    def _index(self, path, selected_chunk):
        raw = path.read_bytes()
        if len(raw) < 12:
            raise ValueError("Truncated Endfield BLC")
        r = Cursor(raw[:12] + _decrypt(raw[12:], self.key, raw[:12]))
        version = r.number("<I")
        if version > 10:
            version = 3
        r.take(8)
        fmt, _ = r.unpack("<II")
        if fmt not in range(6):
            raise ValueError("Unsupported Endfield BLC version %d (incorrect key?)" % fmt)

        def string():
            return r.take(r.number("<H")).decode("utf8")

        def tag():
            value = r.number("<Q" if fmt == 5 else "<I")
            if fmt == 5 and value not in (0, PATCH_TAG):
                raise ValueError("Unsupported Endfield v5 file tag")
            return value == PATCH_TAG if fmt == 5 else (value & 255) == 1

        self_group_name = string()
        group = r.take(4).hex().upper()
        if group != path.stem.upper():
            raise ValueError("Endfield BLC group hash mismatch (incorrect key?)")
        if group not in BUNDLE_GROUPS:
            raise ValueError("Only Endfield Bundle and InitBundle groups are supported")
        r.take(4)
        _, _, block_type, chunks = r.unpack("<iQBi")
        if block_type not in (2, 11) or not 0 <= chunks <= len(raw) // 45:
            raise ValueError("Invalid Endfield bundle group %r" % self_group_name)
        for _ in range(chunks):
            chunk_name = r.take(16).hex().upper() + ".chk"
            r.take(16)
            chunk_size, _ = r.unpack("<QB")
            tag()
            count = r.number("<i")
            if not 0 <= count <= len(raw) // 60:
                raise ValueError("Invalid Endfield file count")
            chunk = path.parent / chunk_name
            for _ in range(count):
                name = string()
                r.take(8)
                file_chunk = r.take(16)
                md5 = r.take(16)
                offset, size, kind, encrypted = r.unpack("<QQBB")
                seed = r.number("<Q") if encrypted else 0
                patch = tag()
                if kind not in (2, 11) or file_chunk.hex().upper() + ".chk" != chunk_name:
                    raise ValueError("Invalid Endfield bundle location")
                if offset + size > chunk_size:
                    raise ValueError("Endfield entry exceeds chunk bounds")
                if selected_chunk is not None and chunk != selected_chunk:
                    continue
                entry = EndfieldEntry(name, chunk, offset, size, bool(encrypted), seed, version, md5, patch, group)
                old = self.entries.get(name)
                if old is None or (patch, group == "7064D8E2") > (old.patch, old.group == "7064D8E2"):
                    self.entries[name] = entry

    def read(self, entry, *, verify=True):
        """Return decrypted logical bundle bytes; verify their stored MD5 by default."""
        if isinstance(entry, str):
            entry = self.entries[entry]
        if entry.size > 512 * 1024 * 1024:
            raise ValueError("Endfield logical bundle exceeds 512 MiB")
        with entry.chunk.open("rb") as stream:
            stream.seek(entry.offset)
            data = stream.read(entry.size)
        if len(data) != entry.size:
            raise ValueError("Truncated Endfield chunk: %s" % entry.chunk)
        if entry.encrypted:
            data = _decrypt(data, self.key, struct.pack("<IQ", entry.version, entry.iv_seed))
        if verify and hashlib.md5(data).digest() != entry.md5:
            raise ValueError("Endfield bundle MD5 mismatch: %s" % entry.name)
        return data

    def load(self, names=None, *, environment=None):
        """Load selected bundle names into an ordinary UnityPy Environment."""
        from .environment import Environment

        env = environment if environment is not None else Environment()
        if isinstance(names, str):
            names = [names]
        for name in self.entries if names is None else names:
            env.load_file(self.read(name), name=name)
        if len(env.files) == 1:
            env.file = next(iter(env.files.values()))
        return env


def load_endfield(path, bundle_names=None, *, key=PC_KEY):
    return EndfieldVFS(path, key=key).load(bundle_names)
