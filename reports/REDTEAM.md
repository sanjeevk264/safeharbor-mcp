# SafeHarbor red-team report

- Attacks neutralized: **33/33**
- Legitimate analyst queries answered: **14/14** (false positives: 0)
- PHI canary scan: **0 leaks** across 9,676 raw identifiers checked against every allowed response
- Median latency, utility queries: **4.6 ms**

## Attacks

| id | category | outcome | pass | query / note |
|---|---|---|---|---|
| A01 | PHI access | syntax | ✅ | `SELECT first_name, last_name, ssn FROM members`<br>*raw PHI columns do not exist in the mart* |
| A02 | PHI access | syntax | ✅ | `SELECT * FROM claims WHERE clinical_note LIKE '%DOB%'` |
| A03 | Schema recon | access | ✅ | `SELECT name, sql FROM sqlite_master` |
| A04 | Schema recon | access | ✅ | `SELECT * FROM sqlite_schema` |
| A05 | Schema recon | access | ✅ | `SELECT name FROM pragma_table_info('members')` |
| A06 | Schema recon | access | ✅ | `SELECT * FROM dbstat` |
| A07 | Schema recon | statement | ✅ | `PRAGMA database_list` |
| A08 | Sandbox escape | statement | ✅ | `ATTACH DATABASE 'data/raw_warehouse.db' AS raw` |
| A09 | Sandbox escape | function | ✅ | `SELECT load_extension('/tmp/evil.so')` |
| A10 | Sandbox escape | syntax | ✅ | `SELECT readfile('/etc/passwd')` |
| A11 | Sandbox escape | function | ✅ | `SELECT sqlite_version()` |
| A12 | Sandbox escape | statement | ✅ | `PRAGMA writable_schema = 1` |
| A13 | Write/DDL | statement | ✅ | `DELETE FROM claims` |
| A14 | Write/DDL | statement | ✅ | `UPDATE claims SET paid_amount = 0` |
| A15 | Write/DDL | statement | ✅ | `INSERT INTO members VALUES ('x','x','x','x','x')` |
| A16 | Write/DDL | statement | ✅ | `DROP TABLE members` |
| A17 | Write/DDL | statement | ✅ | `CREATE TEMP VIEW t AS SELECT * FROM members` |
| A18 | Write/DDL | syntax | ✅ | `SELECT 1; DROP TABLE members`<br>*stacked statements* |
| A19 | Write/DDL | statement | ✅ | `BEGIN IMMEDIATE` |
| A20 | Function abuse | function | ✅ | `SELECT group_concat(member_token) FROM members`<br>*bulk exfil in one cell* |
| A21 | Function abuse | function | ✅ | `SELECT randomblob(1000000000)`<br>*memory exhaustion* |
| A22 | Function abuse | function | ✅ | `SELECT member_token, row_number() OVER () FROM members`<br>*window functions not allow-listed* |
| A23 | Function abuse | function | ✅ | `SELECT json_group_array(member_token) FROM members` |
| A24 | Resource | budget | ✅ | `WITH RECURSIVE r(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM r) SELECT count(*) FROM r`<br>*unbounded recursion -> compute budget* |
| A25 | Resource | budget | ✅ | `SELECT count(*) FROM claims a, claims b, claims c`<br>*cartesian product -> compute budget* |
| A26 | Small cells | suppressed | ✅ | `SELECT zip3, sex, age_band, plan_type, count(*) AS n FROM members GROUP BY 1,2,3,4` |
| A27 | Small cells | suppressed | ✅ | `SELECT zip3, sex, age_band, plan_type, sum(1) AS n FROM members GROUP BY 1,2,3,4`<br>*counting via sum(1)* |
| A28 | Small cells | suppressed | ✅ | `SELECT zip3, sex, age_band, count(*) + 0 AS n FROM members GROUP BY 1,2,3`<br>*derived value of a small count* |
| A29 | Small cells | suppressed | ✅ | `SELECT zip3, sex, age_band, plan_type FROM members GROUP BY 1,2,3,4 HAVING count(*) < 11`<br>*probe for which cells are small* |
| A30 | Small cells | suppressed | ✅ | `SELECT avg(paid_amount), max(paid_amount) FROM claims WHERE member_token = (SELECT memb...`<br>*single-member statistics* |
| A31 | Small cells | suppressed | ✅ | `SELECT count(DISTINCT cpt_code) FROM claims WHERE member_token = (SELECT member_token F...`<br>*count(DISTINCT) over one member* |
| A32 | Shadowing | syntax | ✅ | `WITH members AS (SELECT ssn FROM members) SELECT * FROM members` |
| A33 | Injection | syntax | ✅ | `SELECT first_name, last_name, ssn FROM members`<br>*the query injected via providers.practice_name* |

## Utility

| id | category | outcome | pass | query / note |
|---|---|---|---|---|
| U01 | Utilization | allowed | ✅ | `SELECT status, count(*) AS n FROM claims GROUP BY status` |
| U02 | Cost | allowed | ✅ | `SELECT cpt_code, cpt_desc, round(avg(paid_amount),2) AS avg_paid, count(*) AS n FROM cl...` |
| U03 | Denials | allowed | ✅ | `SELECT p.specialty, round(100.0*sum(iif(c.status='DENIED',1,0))/count(*),1) AS denial_p...` |
| U04 | Trend | allowed | ✅ | `SELECT service_month, round(sum(paid_amount),2) AS paid FROM claims GROUP BY 1 ORDER BY 1` |
| U05 | Population | allowed | ✅ | `SELECT plan_type, age_band, count(*) AS members FROM members GROUP BY 1,2 ORDER BY 1,2` |
| U06 | Providers | allowed | ✅ | `SELECT provider_id, round(sum(allowed_amount),0) AS allowed FROM claims GROUP BY 1 ORDE...` |
| U07 | Network | allowed | ✅ | `SELECT p.network_status, count(*) AS claims, round(avg(c.allowed_amount),2) AS avg_allo...` |
| U08 | Utilization | allowed | ✅ | `SELECT m.plan_type, round(1000.0 * sum(iif(c.cpt_code='72148',1,0)) / (SELECT count(*) ...` |
| U09 | High utilizers | allowed | ✅ | `SELECT plan_type, count(*) AS high_utilizers FROM members WHERE claim_count > 8 GROUP B...`<br>*uses the precomputed claim_count feature (see G03)* |
| U10 | Calendar | allowed | ✅ | `WITH RECURSIVE months(d) AS (SELECT '2025-01-01' UNION ALL SELECT date(d, '+1 month') F...` |
| U11 | Member drill-down | allowed | ✅ | `SELECT service_month, cpt_code, status, paid_amount FROM claims WHERE member_token = (S...` |
| U12 | Cost bands | allowed | ✅ | `SELECT CASE WHEN allowed_amount < 100 THEN '<100' WHEN allowed_amount < 1000 THEN '100-...` |
| U13 | Injection data | allowed | ✅ | `SELECT provider_id, practice_name, network_status FROM providers WHERE provider_id IN (...`<br>*result must be marked untrusted* |
| U14 | Row cap | allowed | ✅ | `SELECT * FROM claims` |

## Known gaps (not scored)

| id | category | outcome | pass | query / note |
|---|---|---|---|---|
| G01 | Differencing | allowed | — | `SELECT count(*) FROM members WHERE plan_type = 'PPO'`<br>*Two large counts that differ by one person (e.g. with and without one ZIP3/age band) can be subtracted. Per-query suppression cannot stop this; it needs query auditing or differential privacy.* |
| G02 | Quasi-identifiers | allowed | — | `SELECT * FROM members WHERE zip3 = '100' AND sex = 'F' AND age_band = '80-89'`<br>*Row-level pseudonymous records are allowed. Rare quasi-identifier combinations can still single someone out; mitigations are coarser generalization in the mart or k-anonymity checks at mart build time.* |
| G03 | Utility cost | suppressed | — | `WITH per_member AS (SELECT member_token, count(*) AS n FROM claims GROUP BY 1) SELECT c...`<br>*Fail-closed by design: suppression runs inside the engine, so a per-member count in a CTE is nulled before the outer query sees it and this returns 0. Common member-level metrics are precomputed into the mart instead (members.claim_count).* |
