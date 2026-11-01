import json
import sqlite3
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from safeharbor import audit, data, redteam
from safeharbor.guard import Policy, QueryGuard

ROOT = Path(__file__).parent.parent
POLICY = ROOT / "policy.toml"


@pytest.fixture(scope="session")
def dbs(tmp_path_factory):
    d = tmp_path_factory.mktemp("data")
    raw, mart = d / "raw.db", d / "mart.db"
    data.build(raw, n_members=800)
    data.build_mart(raw, mart)
    return raw, mart


@pytest.fixture()
def guard(dbs):
    return QueryGuard(str(dbs[1]), Policy.from_toml(tomllib.loads(POLICY.read_text())))


def test_mart_contains_no_direct_identifiers(dbs):
    db = sqlite3.connect(dbs[1])
    cols = {r[1] for t in ("members", "claims", "providers") for r in db.execute(f"PRAGMA table_info({t})")}
    assert not cols & {"first_name", "last_name", "ssn", "dob", "street", "zip", "phone", "email",
                       "member_id", "service_date", "clinical_note", "npi"}


def test_cte_shadowing_cannot_reach_raw_data(guard):
    r = guard.query("WITH members AS (SELECT * FROM members) SELECT * FROM members")
    assert not r.allowed


def test_cte_over_allowed_tables_is_fine(guard):
    r = guard.query("WITH x AS (SELECT status FROM claims) SELECT status, count(*) FROM x GROUP BY 1")
    assert r.allowed and len(r.rows) == 3


def test_virtual_tables_denied(guard):
    for sql in ["SELECT * FROM json_each('[1]')", "SELECT * FROM dbstat",
                "SELECT name FROM pragma_table_list"]:
        assert not guard.query(sql).allowed, sql


def test_suppression_covers_every_aggregate(guard):
    tok = guard.query("SELECT member_token FROM members WHERE claim_count BETWEEN 2 AND 10 LIMIT 1").rows[0][0]
    r = guard.query(f"SELECT count(*), sum(paid_amount), total(1), avg(paid_amount), min(paid_amount), "
                    f"max(paid_amount), count(*) * 1 + 0 FROM claims WHERE member_token = '{tok}'")
    assert r.rows == [[None] * 7]
    assert r.suppressed_cells >= 6


def test_large_aggregates_untouched(guard):
    r = guard.query("SELECT count(*) FROM claims")
    assert r.rows[0][0] > 1000 and r.suppressed_cells == 0


def test_budget_and_row_cap(guard):
    assert guard.query("SELECT count(*) FROM claims a, claims b, claims c").category == "budget"
    r = guard.query("SELECT * FROM claims")
    assert r.allowed and r.truncated and len(r.rows) == 500


def test_audit_chain_detects_tampering(tmp_path):
    log = audit.AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.append(tool="query", sql=f"SELECT {i}", allowed=True)
    assert audit.verify(tmp_path / "a.jsonl")[0]
    # reopen and keep appending: chain must continue
    audit.AuditLog(tmp_path / "a.jsonl").append(tool="query", sql="x", allowed=False)
    assert audit.verify(tmp_path / "a.jsonl") == (True, "6 entries verified")

    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    edited = json.loads(lines[2]); edited["allowed"] = False
    lines[2] = json.dumps(edited, sort_keys=True)
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n")
    ok, msg = audit.verify(tmp_path / "a.jsonl")
    assert not ok and "line 3" in msg

    del lines[2]  # deleting a line instead
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n")
    assert not audit.verify(tmp_path / "a.jsonl")[0]


def test_redteam_suite_passes(dbs):
    s = redteam.run(dbs[1], dbs[0], POLICY)
    a_ok, a_n = s["attacks_neutralized"]
    u_ok, u_n = s["utility_queries_answered"]
    failures = [r["id"] for r in s["results"] if r["suite"] != "gap" and not r["passed"]]
    assert failures == []
    assert a_ok == a_n >= 30 and u_ok == u_n
    assert s["phi_leaks"] == []


def test_mcp_stdio_end_to_end(dbs, tmp_path):
    """Drive the real server process over stdio like an MCP client would."""
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "pytest"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "query", "arguments": {
            "sql": "SELECT status, count(*) AS n FROM claims GROUP BY 1", "purpose": "denial rate check"}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "query", "arguments": {
            "sql": "SELECT * FROM sqlite_master", "purpose": "curious about schema"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "query", "arguments": {
            "sql": "SELECT 1", "purpose": ""}}},
    ]
    audit_path = tmp_path / "audit.jsonl"
    proc = subprocess.run(
        [sys.executable, "-m", "safeharbor.server", "--mart", str(dbs[1]), "--policy", str(POLICY),
         "--audit", str(audit_path)],
        input="\n".join(json.dumps(m) for m in msgs) + "\n", capture_output=True, text=True, cwd=ROOT, timeout=30)
    out = [json.loads(l) for l in proc.stdout.splitlines()]
    assert [o["id"] for o in out] == [1, 2, 3, 4, 5]  # notification got no reply
    assert out[0]["result"]["protocolVersion"] == "2025-06-18"
    assert {t["name"] for t in out[1]["result"]["tools"]} == {"list_tables", "query"}
    assert out[2]["result"]["isError"] is False and out[2]["result"]["structuredContent"]["row_count"] == 3
    assert out[3]["result"]["isError"] is True
    assert out[4]["result"]["isError"] is True  # purpose required
    entries = [json.loads(l) for l in audit_path.read_text().splitlines()]
    assert [e["allowed"] for e in entries] == [True, False, False]
    assert entries[0]["client"] == "pytest" and entries[0]["purpose"] == "denial rate check"
    assert audit.verify(audit_path)[0]
