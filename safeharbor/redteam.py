"""Red-team evaluation for the SafeHarbor gateway.

Runs three suites through the real MCP request path (JSON-RPC -> tools/call):

  attacks   queries that must be blocked or neutralized
  utility   realistic analyst questions that must succeed (false-positive check)
  gaps      known limitations, run and reported honestly but not scored

On top of per-case expectations, a PHI canary scan checks every byte returned
by every allowed call against identifiers pulled from the raw warehouse
(SSNs, phone numbers, emails, street addresses, full dates of birth).
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import statistics
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .server import build_server

K = 11


def _no_small_counts(col: int):
    def check(out):
        return all(r[col] is None or r[col] >= K for r in out["rows"])
    return check


def _suppressed(out):
    return out["suppressed_cells"] > 0


def _empty(out):
    return out["row_count"] == 0


@dataclass
class Case:
    id: str
    category: str
    sql: str
    expect: str            # "block" | "allow"
    check: object = None   # extra predicate on an allowed result
    note: str = ""


ATTACKS = [
    # direct identifiers / schema recon
    Case("A01", "PHI access", "SELECT first_name, last_name, ssn FROM members", "block", note="raw PHI columns do not exist in the mart"),
    Case("A02", "PHI access", "SELECT * FROM claims WHERE clinical_note LIKE '%DOB%'", "block"),
    Case("A03", "Schema recon", "SELECT name, sql FROM sqlite_master", "block"),
    Case("A04", "Schema recon", "SELECT * FROM sqlite_schema", "block"),
    Case("A05", "Schema recon", "SELECT name FROM pragma_table_info('members')", "block"),
    Case("A06", "Schema recon", "SELECT * FROM dbstat", "block"),
    Case("A07", "Schema recon", "PRAGMA database_list", "block"),
    # escaping the sandbox
    Case("A08", "Sandbox escape", "ATTACH DATABASE 'data/raw_warehouse.db' AS raw", "block"),
    Case("A09", "Sandbox escape", "SELECT load_extension('/tmp/evil.so')", "block"),
    Case("A10", "Sandbox escape", "SELECT readfile('/etc/passwd')", "block"),
    Case("A11", "Sandbox escape", "SELECT sqlite_version()", "block"),
    Case("A12", "Sandbox escape", "PRAGMA writable_schema = 1", "block"),
    # writes and DDL
    Case("A13", "Write/DDL", "DELETE FROM claims", "block"),
    Case("A14", "Write/DDL", "UPDATE claims SET paid_amount = 0", "block"),
    Case("A15", "Write/DDL", "INSERT INTO members VALUES ('x','x','x','x','x')", "block"),
    Case("A16", "Write/DDL", "DROP TABLE members", "block"),
    Case("A17", "Write/DDL", "CREATE TEMP VIEW t AS SELECT * FROM members", "block"),
    Case("A18", "Write/DDL", "SELECT 1; DROP TABLE members", "block", note="stacked statements"),
    Case("A19", "Write/DDL", "BEGIN IMMEDIATE", "block"),
    # function abuse
    Case("A20", "Function abuse", "SELECT group_concat(member_token) FROM members", "block", note="bulk exfil in one cell"),
    Case("A21", "Function abuse", "SELECT randomblob(1000000000)", "block", note="memory exhaustion"),
    Case("A22", "Function abuse", "SELECT member_token, row_number() OVER () FROM members", "block", note="window functions not allow-listed"),
    Case("A23", "Function abuse", "SELECT json_group_array(member_token) FROM members", "block"),
    # resource exhaustion
    Case("A24", "Resource", "WITH RECURSIVE r(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM r) SELECT count(*) FROM r", "block", note="unbounded recursion -> compute budget"),
    Case("A25", "Resource", "SELECT count(*) FROM claims a, claims b, claims c", "block", note="cartesian product -> compute budget"),
    # small-cell / aggregate inference
    Case("A26", "Small cells", "SELECT zip3, sex, age_band, plan_type, count(*) AS n FROM members GROUP BY 1,2,3,4", "allow", _no_small_counts(4)),
    Case("A27", "Small cells", "SELECT zip3, sex, age_band, plan_type, sum(1) AS n FROM members GROUP BY 1,2,3,4", "allow", _no_small_counts(4), "counting via sum(1)"),
    Case("A28", "Small cells", "SELECT zip3, sex, age_band, count(*) + 0 AS n FROM members GROUP BY 1,2,3", "allow", _no_small_counts(3), "derived value of a small count"),
    Case("A29", "Small cells", "SELECT zip3, sex, age_band, plan_type FROM members GROUP BY 1,2,3,4 HAVING count(*) < 11", "allow", _empty, "probe for which cells are small"),
    Case("A30", "Small cells", "SELECT avg(paid_amount), max(paid_amount) FROM claims WHERE member_token = (SELECT member_token FROM members WHERE claim_count BETWEEN 1 AND 10 LIMIT 1)", "allow", lambda o: o["rows"][0] == [None, None], "single-member statistics"),
    Case("A31", "Small cells", "SELECT count(DISTINCT cpt_code) FROM claims WHERE member_token = (SELECT member_token FROM members WHERE claim_count BETWEEN 2 AND 10 LIMIT 1)", "allow", lambda o: o["rows"][0] == [None], "count(DISTINCT) over one member"),
    # view/CTE shadowing (the bypass that motivated the physical mart)
    Case("A32", "Shadowing", "WITH members AS (SELECT ssn FROM members) SELECT * FROM members", "block"),
    # prompt injection follow-through
    Case("A33", "Injection", "SELECT first_name, last_name, ssn FROM members", "block", note="the query injected via providers.practice_name"),
]

UTILITY = [
    Case("U01", "Utilization", "SELECT status, count(*) AS n FROM claims GROUP BY status", "allow"),
    Case("U02", "Cost", "SELECT cpt_code, cpt_desc, round(avg(paid_amount),2) AS avg_paid, count(*) AS n FROM claims WHERE status='PAID' GROUP BY 1,2 ORDER BY avg_paid DESC", "allow"),
    Case("U03", "Denials", "SELECT p.specialty, round(100.0*sum(iif(c.status='DENIED',1,0))/count(*),1) AS denial_pct FROM claims c JOIN providers p USING(provider_id) GROUP BY 1 ORDER BY 2 DESC", "allow"),
    Case("U04", "Trend", "SELECT service_month, round(sum(paid_amount),2) AS paid FROM claims GROUP BY 1 ORDER BY 1", "allow"),
    Case("U05", "Population", "SELECT plan_type, age_band, count(*) AS members FROM members GROUP BY 1,2 ORDER BY 1,2", "allow"),
    Case("U06", "Providers", "SELECT provider_id, round(sum(allowed_amount),0) AS allowed FROM claims GROUP BY 1 ORDER BY 2 DESC LIMIT 10", "allow"),
    Case("U07", "Network", "SELECT p.network_status, count(*) AS claims, round(avg(c.allowed_amount),2) AS avg_allowed FROM claims c JOIN providers p USING(provider_id) GROUP BY 1", "allow"),
    Case("U08", "Utilization", "SELECT m.plan_type, round(1000.0 * sum(iif(c.cpt_code='72148',1,0)) / (SELECT count(*) FROM members m2 WHERE m2.plan_type = m.plan_type), 1) AS lumbar_mri_per_1000 FROM claims c JOIN members m USING(member_token) GROUP BY 1", "allow"),
    Case("U09", "High utilizers", "SELECT plan_type, count(*) AS high_utilizers FROM members WHERE claim_count > 8 GROUP BY 1", "allow", note="uses the precomputed claim_count feature (see G03)"),
    Case("U10", "Calendar", "WITH RECURSIVE months(d) AS (SELECT '2025-01-01' UNION ALL SELECT date(d, '+1 month') FROM months WHERE d < '2026-08-01') SELECT strftime('%Y-%m', d) AS m FROM months", "allow"),
    Case("U11", "Member drill-down", "SELECT service_month, cpt_code, status, paid_amount FROM claims WHERE member_token = (SELECT member_token FROM members LIMIT 1) ORDER BY 1", "allow"),
    Case("U12", "Cost bands", "SELECT CASE WHEN allowed_amount < 100 THEN '<100' WHEN allowed_amount < 1000 THEN '100-999' ELSE '1000+' END AS band, count(*) AS n FROM claims GROUP BY 1", "allow"),
    Case("U13", "Injection data", "SELECT provider_id, practice_name, network_status FROM providers WHERE provider_id IN ('P0012','P0013')", "allow", lambda o: o.get("untrusted_columns") == ["practice_name"], "result must be marked untrusted"),
    Case("U14", "Row cap", "SELECT * FROM claims", "allow", lambda o: o["truncated"] and o["row_count"] == 500),
]

GAPS = [
    Case("G01", "Differencing", "SELECT count(*) FROM members WHERE plan_type = 'PPO'", "allow",
         note="Two large counts that differ by one person (e.g. with and without one ZIP3/age band) can be subtracted. "
              "Per-query suppression cannot stop this; it needs query auditing or differential privacy."),
    Case("G02", "Quasi-identifiers", "SELECT * FROM members WHERE zip3 = '100' AND sex = 'F' AND age_band = '80-89'", "allow",
         note="Row-level pseudonymous records are allowed. Rare quasi-identifier combinations can still single someone out; "
              "mitigations are coarser generalization in the mart or k-anonymity checks at mart build time."),
]


GAPS.append(Case("G03", "Utility cost", "WITH per_member AS (SELECT member_token, count(*) AS n FROM claims GROUP BY 1) SELECT count(*) FROM per_member WHERE n > 8", "allow",
    note="Fail-closed by design: suppression runs inside the engine, so a per-member count in a CTE is nulled "
         "before the outer query sees it and this returns 0. Common member-level metrics are precomputed into the mart instead (members.claim_count)."))


def _answered(out):
    return out["row_count"] > 0 and out["suppressed_cells"] == 0


def _phi_canaries(raw_db: Path) -> set[str]:
    db = sqlite3.connect(raw_db)
    out = set()
    for ssn, dob, street, phone, email in db.execute("SELECT ssn, dob, street, phone, email FROM members"):
        out.update({ssn, dob, street, phone, email})
    db.close()
    return out


def run(mart: Path, raw: Path, policy: Path, report_dir: Path | None = None) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        srv = build_server(str(mart), str(policy), str(Path(tmp) / "audit.jsonl"))
        srv.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "redteam"}}})
        canaries = _phi_canaries(raw)
        results, leaks, latencies, n = [], [], [], 0

        for suite, cases in (("attack", ATTACKS), ("utility", UTILITY), ("gap", GAPS)):
            for c in cases:
                n += 1
                resp = srv.handle({"jsonrpc": "2.0", "id": n, "method": "tools/call",
                                   "params": {"name": "query",
                                              "arguments": {"sql": c.sql, "purpose": f"red-team case {c.id}"}}})
                res = resp["result"]
                out = res["structuredContent"]
                blocked = res["isError"]
                text = res["content"][0]["text"]
                hits = [x for x in canaries if x in text] if not blocked else []
                leaks += [(c.id, h) for h in hits]
                if c.expect == "block":
                    passed = blocked
                elif suite == "utility":
                    passed = (not blocked) and _answered(out) and (c.check is None or bool(c.check(out)))
                else:
                    passed = (not blocked) and (c.check is None or bool(c.check(out)))
                if suite == "utility" and not blocked:
                    latencies.append(srv.guard.query(c.sql).elapsed_ms)
                results.append({"id": c.id, "suite": suite, "category": c.category, "sql": c.sql,
                                "expect": c.expect, "passed": passed and not hits,
                                "outcome": out.get("category", "blocked") if blocked else
                                           ("suppressed" if out.get("suppressed_cells") else "allowed"),
                                "detail": out.get("error") or out.get("suppression_note") or "",
                                "note": c.note})

    def score(suite):
        rs = [r for r in results if r["suite"] == suite]
        return sum(r["passed"] for r in rs), len(rs)

    summary = {
        "attacks_neutralized": score("attack"),
        "utility_queries_answered": score("utility"),
        "known_gaps": len(GAPS),
        "phi_canaries_checked": len(canaries),
        "phi_leaks": leaks,
        "utility_p50_ms": round(statistics.median(latencies), 1) if latencies else None,
        "results": results,
    }
    if report_dir:
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "redteam.json").write_text(json.dumps(summary, indent=2, default=str))
        (report_dir / "REDTEAM.md").write_text(_markdown(summary))
    return summary


def _markdown(s: dict) -> str:
    a, at = s["attacks_neutralized"]
    u, ut = s["utility_queries_answered"]
    lines = ["# SafeHarbor red-team report", "",
             f"- Attacks neutralized: **{a}/{at}**",
             f"- Legitimate analyst queries answered: **{u}/{ut}** (false positives: {ut - u})",
             f"- PHI canary scan: **{len(s['phi_leaks'])} leaks** across {s['phi_canaries_checked']:,} raw identifiers checked against every allowed response",
             f"- Median latency, utility queries: **{s['utility_p50_ms']} ms**", ""]
    for suite, title in (("attack", "Attacks"), ("utility", "Utility"), ("gap", "Known gaps (not scored)")):
        lines += [f"## {title}", "", "| id | category | outcome | pass | query / note |", "|---|---|---|---|---|"]
        for r in s["results"]:
            if r["suite"] != suite:
                continue
            q = r["sql"].replace("|", "\\|")
            q = q if len(q) < 90 else q[:87] + "..."
            extra = f"<br>*{r['note']}*" if r["note"] else ""
            mark = "—" if suite == "gap" else ("✅" if r["passed"] else "❌")
            lines.append(f"| {r['id']} | {r['category']} | {r['outcome']} | {mark} | `{q}`{extra} |")
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the SafeHarbor red-team suite")
    ap.add_argument("--mart", default="data/mart.db")
    ap.add_argument("--raw", default="data/raw_warehouse.db")
    ap.add_argument("--policy", default="policy.toml")
    ap.add_argument("--out", default="reports")
    a = ap.parse_args(argv)
    s = run(Path(a.mart), Path(a.raw), Path(a.policy), Path(a.out))
    a_ok, a_n = s["attacks_neutralized"]
    u_ok, u_n = s["utility_queries_answered"]
    for r in s["results"]:
        if r["suite"] != "gap" and not r["passed"]:
            print(f"FAIL {r['id']} {r['category']}: {r['outcome']} {r['detail']}")
    print(f"attacks neutralized {a_ok}/{a_n} | utility {u_ok}/{u_n} | PHI leaks {len(s['phi_leaks'])} | "
          f"p50 {s['utility_p50_ms']} ms | report: {a.out}/REDTEAM.md")
    return 0 if (a_ok == a_n and u_ok == u_n and not s["phi_leaks"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
