"""Audit logging: a hook that writes each scan result as one tamper-evident JSON line.

By default the scanned text is NOT written — only its SHA-256 and length — so the
audit trail itself never becomes a store of user prompts, secrets or PII.

    guard.add_hook(AuditLogger("guardlayer-audit.jsonl", min_verdict=Verdict.FLAG))

**Hash chain.** Every entry carries `seq`, the previous entry's hash (`prev_hash`) and its
own `entry_hash` (SHA-256 of the canonical JSON of everything else). Editing, deleting,
inserting or reordering any line breaks the chain, and `verify_audit_log` (or
`guardlayer audit verify`) reports the first bad line. Pass a `signer` (Ed25519, needs the
`signing` extra) and each entry hash is also signed, so rebuilding a consistent fake chain
needs the private key. Truncating the *tail* of a log is only detectable against a
known-good head: record `verification.head_hash` somewhere else (a ticket, a SIEM, git).

One `AuditLogger` should own a file: two writers appending to the same file fork the chain.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from guardlayer.models import ScanResult, Verdict

logger = logging.getLogger("guardlayer.audit")

GENESIS_HASH = "0" * 64
_SENSITIVE_METADATA = {"hidden_preview", "matched", "url", "token"}


def canonical_json(entry: dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def entry_digest(entry: dict[str, Any]) -> str:
    """SHA-256 of an entry without its own hash and signature fields."""
    body = {k: v for k, v in entry.items() if k not in {"entry_hash", "signature", "key_id"}}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


# ------------------------------------------------------------------------------------ signing
def _crypto() -> Any:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError("Signed audit logs need the 'signing' extra: pip install 'guardlayer[signing]'") from exc
    return serialization, ed25519


def _key_id(public_key: Any) -> str:
    serialization, _ = _crypto()
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


class AuditSigner:
    """Signs audit entry hashes with an Ed25519 private key."""

    def __init__(self, private_key: Any) -> None:
        self._key = private_key
        self.key_id = _key_id(private_key.public_key())

    @classmethod
    def generate(cls) -> AuditSigner:
        _, ed25519 = _crypto()
        return cls(ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, source: str | Path | bytes, password: bytes | None = None) -> AuditSigner:
        serialization, ed25519 = _crypto()
        data = source if isinstance(source, bytes) else Path(source).read_bytes()
        key = serialization.load_pem_private_key(data, password=password)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise ValueError("audit signing key must be an Ed25519 private key")
        return cls(key)

    def sign(self, digest: str) -> str:
        return base64.b64encode(self._key.sign(digest.encode("ascii"))).decode("ascii")

    def private_pem(self) -> bytes:
        serialization, _ = _crypto()
        return self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    def public_pem(self) -> bytes:
        serialization, _ = _crypto()
        return self._key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_public_key(source: str | Path | bytes) -> Any:
    serialization, ed25519 = _crypto()
    data = source if isinstance(source, bytes) else Path(source).read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("audit verification key must be an Ed25519 public key")
    return key


# ------------------------------------------------------------------------------------- logger
class AuditLogger:
    def __init__(
        self,
        path: str | Path | None = None,
        *,
        stream: IO[str] | None = None,
        min_verdict: Verdict = Verdict.ALLOW,
        include_text: bool = False,
        use_logging: bool = False,
        chain: bool = True,
        signer: AuditSigner | str | Path | None = None,
    ) -> None:
        if path is None and stream is None and not use_logging:
            raise ValueError("AuditLogger needs a path, a stream, or use_logging=True")
        self.path = Path(path) if path else None
        self.stream = stream
        self.min_verdict = Verdict(min_verdict)
        self.include_text = include_text
        self.use_logging = use_logging
        self.chain = chain or signer is not None
        self.signer = signer if isinstance(signer, AuditSigner) or signer is None else AuditSigner.from_pem(signer)
        self._lock = threading.Lock()
        self._seq, self._prev = 0, GENESIS_HASH
        if self.chain and self.path and self.path.exists():
            self._resume()

    def _resume(self) -> None:
        """Continue the chain of an existing log file from its last entry."""
        assert self.path is not None
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return
        entry = json.loads(last)
        if "entry_hash" not in entry or "seq" not in entry:
            raise ValueError(f"{self.path} holds unchained audit entries; start a new file for a chained log")
        self._seq, self._prev = int(entry["seq"]) + 1, entry["entry_hash"]

    def record(self, result: ScanResult) -> dict[str, Any]:
        entry = result.to_dict(include_text=self.include_text)
        entry["text_sha256"] = hashlib.sha256(result.text.encode("utf-8")).hexdigest()
        entry["text_length"] = len(result.text)
        if not self.include_text:
            for d in entry["detections"]:  # matched values (e.g. secrets) must not leak into logs
                d["metadata"] = {k: v for k, v in d["metadata"].items() if k not in _SENSITIVE_METADATA}
        return json.loads(json.dumps(entry, ensure_ascii=False, default=str))  # the exact form that gets hashed

    def _seal(self, entry: dict[str, Any]) -> dict[str, Any]:
        entry["seq"], entry["prev_hash"] = self._seq, self._prev
        entry["entry_hash"] = entry_digest(entry)
        if self.signer is not None:
            entry["key_id"] = self.signer.key_id
            entry["signature"] = self.signer.sign(entry["entry_hash"])
        self._seq, self._prev = self._seq + 1, entry["entry_hash"]
        return entry

    def __call__(self, result: ScanResult) -> None:
        # effective_verdict: in observe mode, log what enforcement *would* have done.
        if result.effective_verdict < self.min_verdict:
            return
        entry = self.record(result)
        with self._lock:
            if self.chain:
                entry = self._seal(entry)
            line = json.dumps(entry, ensure_ascii=False, default=str)
            if self.path:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            if self.stream:
                self.stream.write(line + "\n")
                self.stream.flush()
        if self.use_logging:
            level = logging.WARNING if result.effective_verdict >= Verdict.REVIEW else logging.INFO
            logger.log(level, line)


# ------------------------------------------------------------------------------------- verify
@dataclass
class AuditVerification:
    ok: bool
    entries: int  # entries checked before stopping
    head_hash: str | None  # hash of the last valid entry; anchor it elsewhere to detect truncation
    signed: int = 0  # entries with a valid signature
    error: str | None = None
    line: int | None = None  # 1-based line number of the first problem

    def summary(self) -> str:
        if self.ok:
            sig = f", {self.signed} signatures valid" if self.signed else ""
            return f"OK: {self.entries} entries, chain intact{sig}. head {self.head_hash}"
        return f"FAILED at line {self.line}: {self.error} ({self.entries} entries valid before it)"


def verify_audit_log(
    path: str | Path,
    *,
    public_key: Any | str | Path | bytes | None = None,
    expected_head: str | None = None,
) -> AuditVerification:
    """Check a chained audit log: sequence, hash links, entry hashes and (with `public_key`) signatures.

    `expected_head`, when given, must be the hash of the last entry — this detects truncation.
    """
    key = load_public_key(public_key) if isinstance(public_key, (str, Path, bytes)) else public_key
    key_id = _key_id(key) if key is not None else None
    prev, seq, signed, count = GENESIS_HASH, 0, 0, 0

    def fail(msg: str, lineno: int) -> AuditVerification:
        return AuditVerification(False, count, prev if count else None, signed, msg, lineno)

    with Path(path).open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                return fail(f"not valid JSON ({exc.msg})", lineno)
            if not isinstance(entry, dict) or "entry_hash" not in entry:
                return fail("entry is not part of a hash chain", lineno)
            if entry.get("seq") != seq:
                return fail(f"sequence gap: expected seq {seq}, found {entry.get('seq')}", lineno)
            if entry.get("prev_hash") != prev:
                return fail("prev_hash does not match the previous entry (line deleted, inserted or reordered)", lineno)
            if entry_digest(entry) != entry["entry_hash"]:
                return fail("entry_hash does not match the content (entry was modified)", lineno)
            if key is not None:
                sig = entry.get("signature")
                if not sig:
                    return fail("entry is not signed", lineno)
                if entry.get("key_id") != key_id:
                    return fail(f"signed with a different key ({entry.get('key_id')})", lineno)
                try:
                    key.verify(base64.b64decode(sig), entry["entry_hash"].encode("ascii"))
                except Exception:
                    return fail("invalid signature", lineno)
                signed += 1
            prev, seq, count = entry["entry_hash"], seq + 1, count + 1

    if expected_head is not None and prev != expected_head:
        return AuditVerification(False, count, prev, signed, "head hash differs from the expected head (log truncated or replaced)", None)
    return AuditVerification(True, count, prev if count else None, signed)
