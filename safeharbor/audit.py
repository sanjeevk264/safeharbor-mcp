"""Tamper-evident audit log.

Every tool call is appended as one JSON line. Each entry stores the SHA-256 of
the previous entry, so editing, deleting or reordering any line breaks the
chain from that point on. `verify()` reports the first broken line.

HIPAA's audit-control standard (45 CFR 164.312(b)) requires recording activity
in systems containing ePHI; a hash chain makes the record trustworthy.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

GENESIS = "0" * 64


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev = GENESIS
        self._seq = 0
        if self.path.exists():
            lines = [l for l in self.path.read_text().splitlines() if l.strip()]
            if lines:
                last = json.loads(lines[-1])
                self._prev, self._seq = last["hash"], last["seq"]

    def append(self, **fields) -> dict:
        self._seq += 1
        entry = {"seq": self._seq, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 **fields, "prev": self._prev}
        entry["hash"] = _digest(entry)
        with self.path.open("a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        self._prev = entry["hash"]
        return entry


def verify(path: str | Path) -> tuple[bool, str]:
    prev = GENESIS
    lines = [l for l in Path(path).read_text().splitlines() if l.strip()]
    for i, line in enumerate(lines, 1):
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            return False, f"line {i}: not valid JSON"
        if e.get("prev") != prev:
            return False, f"line {i} (seq {e.get('seq')}): chain broken (entry missing, reordered or altered before it)"
        if _digest(e) != e.get("hash"):
            return False, f"line {i} (seq {e.get('seq')}): contents altered"
        prev = e["hash"]
    return True, f"{len(lines)} entries verified"


if __name__ == "__main__":
    import sys
    ok, msg = verify(sys.argv[1] if len(sys.argv) > 1 else "logs/audit.jsonl")
    print(("OK: " if ok else "TAMPERED: ") + msg)
    sys.exit(0 if ok else 1)
