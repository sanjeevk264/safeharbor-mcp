"""Query guard: the enforcement layer between an AI agent and a PHI database.

Defense in depth, all enforced by the database engine rather than by parsing
SQL text (regex SQL filters are trivially bypassed):

0. The connection points at a de-identified mart; raw PHI is not in the file.
1. Read-only connection (URI mode=ro) and PRAGMA query_only.
2. SQLite authorizer callback, consulted by the engine for every table/column
   read, function call and statement type during query *compilation*:
     - only allow-listed tables (sqlite_master/schema recon is denied)
     - only allow-listed SQL functions
     - no PRAGMA, ATTACH, writes, DDL or transactions
3. Small-cell suppression inside the engine: aggregate functions are replaced
   with versions that return NULL when computed over fewer than k rows, so
   derived values (count(*) + 0, avg, sum(1), HAVING filters) are covered too.
4. Resource limits: VM-instruction budget, wall-clock timeout, row cap.
"""
from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass, field

A = sqlite3  # action-code constants live on the module

ACTION_NAMES = {
    A.SQLITE_INSERT: "INSERT", A.SQLITE_UPDATE: "UPDATE", A.SQLITE_DELETE: "DELETE",
    A.SQLITE_PRAGMA: "PRAGMA", A.SQLITE_ATTACH: "ATTACH", A.SQLITE_DETACH: "DETACH",
    A.SQLITE_CREATE_TABLE: "CREATE TABLE", A.SQLITE_CREATE_VIEW: "CREATE VIEW",
    A.SQLITE_CREATE_TEMP_TABLE: "CREATE TEMP TABLE", A.SQLITE_CREATE_TEMP_VIEW: "CREATE TEMP VIEW",
    A.SQLITE_DROP_TABLE: "DROP TABLE", A.SQLITE_DROP_VIEW: "DROP VIEW",
    A.SQLITE_TRANSACTION: "TRANSACTION", A.SQLITE_SAVEPOINT: "SAVEPOINT",
    A.SQLITE_ALTER_TABLE: "ALTER TABLE", A.SQLITE_ANALYZE: "ANALYZE", A.SQLITE_REINDEX: "REINDEX",
    A.SQLITE_CREATE_INDEX: "CREATE INDEX", A.SQLITE_CREATE_TRIGGER: "CREATE TRIGGER",
    A.SQLITE_CREATE_VTABLE: "CREATE VIRTUAL TABLE",
}
ALLOWED_ACTIONS = {A.SQLITE_SELECT, A.SQLITE_READ, A.SQLITE_FUNCTION, A.SQLITE_RECURSIVE}


@dataclass
class Policy:
    allowed_tables: set[str]
    allowed_functions: set[str]
    k_min: int = 11
    max_rows: int = 500
    max_vm_steps: int = 50_000_000
    timeout_s: float = 5.0
    untrusted_text_columns: set[str] = field(default_factory=set)

    @classmethod
    def from_toml(cls, data: dict) -> "Policy":
        return cls(
            allowed_tables=set(data["access"]["tables"]),
            allowed_functions={f.lower() for f in data["access"]["functions"]},
            k_min=data["privacy"]["k_min"],
            max_rows=data["limits"]["max_rows"],
            max_vm_steps=data["limits"]["max_vm_steps"],
            timeout_s=data["limits"]["timeout_s"],
            untrusted_text_columns=set(data["privacy"].get("untrusted_text_columns", [])),
        )


@dataclass
class QueryResult:
    allowed: bool
    columns: list[str] = field(default_factory=list)
    rows: list[list] = field(default_factory=list)
    truncated: bool = False
    suppressed_cells: int = 0
    reason: str = ""
    category: str = ""   # why it was denied: access | statement | function | budget | syntax
    elapsed_ms: float = 0.0


class _KAgg:
    """Base for k-suppressed aggregates. Counts contributing rows."""
    k = 11

    def __init__(self):
        self.n = 0

    def _suppress(self, value):
        if 0 < self.n < self.k:
            _KAgg.suppressed += 1
            return None
        return value

    suppressed = 0


def _make_aggregates(k: int):
    class Count(_KAgg):
        def step(self, *args):
            if not args or args[0] is not None:
                self.n += 1
        def finalize(self):
            return self._suppress(self.n)

    class Sum(_KAgg):
        def __init__(self):
            super().__init__(); self.s = None
        def step(self, x):
            if x is not None:
                self.n += 1
                self.s = x if self.s is None else self.s + x
        def finalize(self):
            return self._suppress(self.s)

    class Total(Sum):
        def finalize(self):
            return self._suppress(float(self.s or 0.0))

    class Avg(Sum):
        def finalize(self):
            return self._suppress(None if self.s is None else self.s / self.n)

    class Min(_KAgg):
        def __init__(self):
            super().__init__(); self.v = None
        def step(self, x):
            if x is not None:
                self.n += 1
                self.v = x if self.v is None or x < self.v else self.v
        def finalize(self):
            return self._suppress(self.v)

    class Max(Min):
        def step(self, x):
            if x is not None:
                self.n += 1
                self.v = x if self.v is None or x > self.v else self.v

    for c in (Count, Sum, Total, Avg, Min, Max):
        c.k = k
    return {"count": (Count, (0, 1)), "sum": (Sum, (1,)), "total": (Total, (1,)),
            "avg": (Avg, (1,)), "min": (Min, (1,)), "max": (Max, (1,))}


class QueryGuard:
    def __init__(self, db_path: str, policy: Policy):
        self.policy = policy
        self.db_path = db_path
        self.conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, check_same_thread=False)
        self.conn.execute("PRAGMA query_only = ON")
        for name, (cls, nargs) in _make_aggregates(policy.k_min).items():
            for n in nargs:
                self.conn.create_aggregate(name, n, cls)
        self._denials: list[tuple[str, str]] = []
        self.conn.set_authorizer(self._authorize)
        self._deadline = 0.0
        self._steps = 0
        self.conn.set_progress_handler(self._progress, 10_000)

    # --- authorizer --------------------------------------------------------------
    def _authorize(self, action, arg1, arg2, dbname, source):
        p = self.policy
        if action == A.SQLITE_SELECT or action == A.SQLITE_RECURSIVE:
            return A.SQLITE_OK
        if action == A.SQLITE_READ:
            table, column = arg1, arg2
            if table in p.allowed_tables:
                return A.SQLITE_OK
            if dbname is None:
                # CTE reference: SQLite passes no database name. The CTE's own
                # body was authorized read-by-read, so it holds only allowed data.
                # Virtual tables (pragma_*, dbstat, json_each) report 'main' and
                # fall through to the deny below.
                return A.SQLITE_OK
            self._denials.append(("access", f"read of {table}.{column or '*'} is not permitted; "
                                            f"available tables: {sorted(p.allowed_tables)}"))
            return A.SQLITE_DENY
        if action == A.SQLITE_FUNCTION:
            if (arg2 or "").lower() in p.allowed_functions:
                return A.SQLITE_OK
            self._denials.append(("function", f"function {arg2}() is not on the allow-list"))
            return A.SQLITE_DENY
        self._denials.append(("statement", f"{ACTION_NAMES.get(action, f'action {action}')} statements are not permitted (read-only access)"))
        return A.SQLITE_DENY

    def _progress(self):
        self._steps += 10_000
        if self._steps > self.policy.max_vm_steps or time.monotonic() > self._deadline:
            return 1  # non-zero aborts the statement
        return 0

    # --- public API ----------------------------------------------------------------
    def query(self, sql: str) -> QueryResult:
        t0 = time.monotonic()
        self._denials.clear()
        self._steps = 0
        self._deadline = t0 + self.policy.timeout_s
        _KAgg.suppressed = 0
        try:
            cur = self.conn.execute(sql)
            cols = [d[0] for d in cur.description or []]
            rows = cur.fetchmany(self.policy.max_rows + 1)
        except sqlite3.DatabaseError as e:
            msg = str(e)
            ms = (time.monotonic() - t0) * 1000
            if self._denials:
                cat, reason = self._denials[0]
                return QueryResult(False, reason=reason, category=cat, elapsed_ms=ms)
            if "interrupted" in msg:
                return QueryResult(False, reason="query exceeded the compute budget; add filters or aggregate",
                                   category="budget", elapsed_ms=ms)
            return QueryResult(False, reason=f"SQL error: {msg}", category="syntax", elapsed_ms=ms)
        except sqlite3.Warning as e:  # e.g. multiple statements
            return QueryResult(False, reason=f"{e}", category="statement",
                               elapsed_ms=(time.monotonic() - t0) * 1000)
        except sqlite3.ProgrammingError as e:
            return QueryResult(False, reason=f"{e}", category="statement",
                               elapsed_ms=(time.monotonic() - t0) * 1000)
        truncated = len(rows) > self.policy.max_rows
        return QueryResult(True, cols, [list(r) for r in rows[: self.policy.max_rows]], truncated,
                           _KAgg.suppressed, elapsed_ms=(time.monotonic() - t0) * 1000)

    def catalog(self) -> dict[str, list[dict]]:
        """Column metadata for the governed tables (read with a separate, unguarded connection)."""
        admin = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        out = {}
        for v in sorted(self.policy.allowed_tables):
            out[v] = [{"name": r[1], "type": r[2] or "TEXT",
                       "untrusted_text": r[1] in self.policy.untrusted_text_columns}
                      for r in admin.execute(f"PRAGMA table_info({v})")]
        admin.close()
        return out


def fingerprint(sql: str) -> str:
    """Normalize SQL for logging/grouping (literals stripped)."""
    s = re.sub(r"'(?:[^']|'')*'", "?", sql)
    s = re.sub(r"\b\d+(\.\d+)?\b", "?", s)
    return re.sub(r"\s+", " ", s).strip().lower()
