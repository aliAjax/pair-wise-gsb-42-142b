"""Financial-crime investigation and sanctions-screening service."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from difflib import SequenceMatcher
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "financial_crime.db"
HIGH_RISK_COUNTRIES = {"KP", "IR", "SY", "CU", "RU"}
SENSITIVE_ROLES = {"investigator", "supervisor", "director", "auditor"}


class DomainError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_name(value: str) -> str:
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", (value or "").casefold())


def require_role(role: str, allowed: set[str], action: str) -> None:
    if role not in allowed:
        raise DomainError("角色无权执行：%s" % action, 403)


def clean_actor(actor: str) -> str:
    actor = (actor or "").strip()
    if not actor:
        raise DomainError("缺少操作人")
    return actor


def name_similarity(left: str, right: str) -> float:
    left, right = normalize_name(left), normalize_name(right)
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    return SequenceMatcher(None, left, right).ratio()


class FinancialCrimeService:
    def __init__(self, db_path: str | os.PathLike[str] = DEFAULT_DB):
        self.db_path = str(db_path)
        self._init_schema()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    canonical_name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL,
                    aliases TEXT NOT NULL DEFAULT '[]',
                    risk_level TEXT NOT NULL DEFAULT 'low',
                    frozen INTEGER NOT NULL DEFAULT 0,
                    merged_into INTEGER REFERENCES entities(id),
                    version INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS customers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id INTEGER NOT NULL REFERENCES entities(id),
                    customer_no TEXT NOT NULL UNIQUE,
                    country TEXT NOT NULL,
                    occupation TEXT NOT NULL DEFAULT '',
                    allowlisted INTEGER NOT NULL DEFAULT 0,
                    risk_score REAL NOT NULL DEFAULT 0,
                    merged_into INTEGER REFERENCES customers(id),
                    version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS watchlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    list_name TEXT NOT NULL,
                    name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL,
                    countries TEXT NOT NULL DEFAULT '[]',
                    version INTEGER NOT NULL DEFAULT 1,
                    active INTEGER NOT NULL DEFAULT 1,
                    updated_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(list_name, normalized_name)
                );
                CREATE TABLE IF NOT EXISTS watchlist_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    list_name TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'publishing',
                    content_hash TEXT NOT NULL,
                    entry_count INTEGER NOT NULL,
                    published_by TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    origin TEXT NOT NULL DEFAULT 'published',
                    UNIQUE(list_name, version)
                );
                CREATE TABLE IF NOT EXISTS watchlist_snapshot_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL REFERENCES watchlist_snapshots(id),
                    list_name TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    seq INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL,
                    countries TEXT NOT NULL DEFAULT '[]',
                    UNIQUE(snapshot_id, seq)
                );
                CREATE TABLE IF NOT EXISTS review_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id INTEGER NOT NULL REFERENCES transactions(id),
                    list_name TEXT NOT NULL,
                    old_snapshot_id INTEGER REFERENCES watchlist_snapshots(id),
                    new_snapshot_id INTEGER NOT NULL REFERENCES watchlist_snapshots(id),
                    change_type TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    superseded_task_id INTEGER REFERENCES review_tasks(id),
                    resolution TEXT,
                    resolved_by TEXT,
                    resolved_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_reviews (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    task_id INTEGER REFERENCES review_tasks(id),
                    transaction_id INTEGER REFERENCES transactions(id),
                    list_name TEXT NOT NULL,
                    old_snapshot_id INTEGER,
                    new_snapshot_id INTEGER NOT NULL,
                    change_type TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    txn_ref TEXT NOT NULL UNIQUE,
                    customer_id INTEGER NOT NULL REFERENCES customers(id),
                    entity_id INTEGER NOT NULL REFERENCES entities(id),
                    amount REAL NOT NULL,
                    currency TEXT NOT NULL,
                    counterparty_name TEXT NOT NULL,
                    counterparty_country TEXT NOT NULL,
                    status TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    reason TEXT NOT NULL,
                    screen_snapshot_id INTEGER REFERENCES watchlist_snapshots(id),
                    screen_detail TEXT NOT NULL DEFAULT '{}',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL UNIQUE,
                    entity_id INTEGER NOT NULL REFERENCES entities(id),
                    transaction_id INTEGER REFERENCES transactions(id),
                    reason TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new',
                    occurrences INTEGER NOT NULL DEFAULT 1,
                    case_id INTEGER,
                    dismissed_reason TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_no TEXT NOT NULL UNIQUE,
                    entity_id INTEGER NOT NULL REFERENCES entities(id),
                    alert_id INTEGER REFERENCES alerts(id),
                    status TEXT NOT NULL DEFAULT 'open',
                    risk_score REAL NOT NULL,
                    assignee TEXT,
                    freeze_target INTEGER NOT NULL DEFAULT 0,
                    report_ref TEXT,
                    version INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id),
                    actor TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS entity_merges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER REFERENCES cases(id),
                    entity_id INTEGER REFERENCES entities(id),
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_txn_entity ON transactions(entity_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status, risk_score DESC);
                CREATE INDEX IF NOT EXISTS idx_snapshot_list ON watchlist_snapshots(list_name, version);
                CREATE INDEX IF NOT EXISTS idx_snapshot_entries ON watchlist_snapshot_entries(snapshot_id);
                CREATE INDEX IF NOT EXISTS idx_review_tasks_status ON review_tasks(status, id);
                CREATE INDEX IF NOT EXISTS idx_case_reviews_case ON case_reviews(case_id, id);
                """
            )
            self._migrate_schema(conn)
            self._recover_interrupted_batches(conn)
            self._migrate_legacy_watchlist(conn)

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        existing = {r["name"] for r in conn.execute("PRAGMA table_info(transactions)").fetchall()}
        if "screen_snapshot_id" not in existing:
            conn.execute("ALTER TABLE transactions ADD COLUMN screen_snapshot_id INTEGER")
        if "screen_detail" not in existing:
            conn.execute("ALTER TABLE transactions ADD COLUMN screen_detail TEXT NOT NULL DEFAULT '{}'")

    def _recover_interrupted_batches(self, conn: sqlite3.Connection) -> None:
        """中断的发布事务不会留下半成品；残留 publishing 行只可能来自旧进程崩溃后的提交边界。"""
        stale = conn.execute("SELECT id FROM watchlist_snapshots WHERE status='publishing'").fetchall()
        for row in stale:
            conn.execute("DELETE FROM watchlist_snapshot_entries WHERE snapshot_id=?", (row["id"],))
            conn.execute("DELETE FROM watchlist_snapshots WHERE id=?", (row["id"],))

    def _migrate_legacy_watchlist(self, conn: sqlite3.Connection) -> None:
        """旧逐条名单：每个名单首次启动时冻结为 v1 历史快照，后续名单维护只能发布新批次。"""
        rows = conn.execute(
            "SELECT list_name FROM watchlist WHERE active=1 GROUP BY list_name"
        ).fetchall()
        for row in rows:
            list_name = row["list_name"]
            if conn.execute(
                "SELECT 1 FROM watchlist_snapshots WHERE list_name=?", (list_name,)
            ).fetchone():
                continue
            entries = conn.execute(
                "SELECT name,normalized_name,countries FROM watchlist WHERE list_name=? AND active=1 ORDER BY id",
                (list_name,),
            ).fetchall()
            self._publish_snapshot(
                conn, list_name,
                [{"name": r["name"], "countries": json.loads(r["countries"])} for r in entries],
                actor="system-migration", note="旧逐条名单迁移的第一版历史快照", origin="migration",
            )

    def _audit(self, conn: sqlite3.Connection, actor: str, action: str, details: dict[str, Any],
               entity_id: int | None = None, case_id: int | None = None) -> None:
        conn.execute(
            "INSERT INTO timeline(case_id,entity_id,actor,action,details,created_at) VALUES(?,?,?,?,?,?)",
            (case_id, entity_id, actor, action, json.dumps(details, ensure_ascii=False, sort_keys=True), utcnow()),
        )

    def _resolve_entity(self, conn: sqlite3.Connection, entity_id: int) -> sqlite3.Row:
        seen = set()
        current = entity_id
        while True:
            if current in seen:
                raise DomainError("实体合并关系存在循环", 409)
            seen.add(current)
            row = conn.execute("SELECT * FROM entities WHERE id=?", (current,)).fetchone()
            if not row:
                raise DomainError("实体不存在", 404)
            if row["merged_into"] is None:
                return row
            current = row["merged_into"]

    def create_entity(self, actor: str, role: str, entity_type: str, canonical_name: str,
                      aliases: list[str] | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"analyst", "investigator", "supervisor"}, "创建实体")
        entity_type = entity_type.strip().lower()
        canonical_name = canonical_name.strip()
        if entity_type not in {"person", "organization"} or not canonical_name:
            raise DomainError("实体类型或名称无效")
        normalized = normalize_name(canonical_name)
        clean_aliases = sorted({a.strip() for a in (aliases or []) if a and a.strip()}, key=str.casefold)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing_entities = conn.execute(
                "SELECT canonical_name,aliases FROM entities WHERE merged_into IS NULL"
            ).fetchall()
            for row in existing_entities:
                known_names = [row["canonical_name"]] + json.loads(row["aliases"])
                if any(normalize_name(item) == normalized for item in known_names):
                    raise DomainError("实体名称或别名已存在，应使用已有实体或执行合并", 409)
            try:
                cur = conn.execute(
                    """INSERT INTO entities(entity_type,canonical_name,normalized_name,aliases,created_by,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (entity_type, canonical_name, normalized, json.dumps(clean_aliases, ensure_ascii=False), actor, utcnow(), utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("实体已存在", 409) from exc
            self._audit(conn, actor, "entity.created", {"name": canonical_name}, cur.lastrowid)
            return dict(conn.execute("SELECT * FROM entities WHERE id=?", (cur.lastrowid,)).fetchone())

    def add_alias(self, actor: str, role: str, entity_id: int, alias: str,
                  expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"analyst", "investigator", "supervisor"}, "维护实体别名")
        alias = alias.strip()
        if not alias:
            raise DomainError("别名不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            entity = self._resolve_entity(conn, entity_id)
            if entity["merged_into"] is not None:
                raise DomainError("请在主实体上维护别名", 409)
            if entity["version"] != int(expected_version):
                raise DomainError("实体已变化，请刷新后重试", 409)
            aliases = json.loads(entity["aliases"])
            normalized = normalize_name(alias)
            conflict = conn.execute(
                "SELECT id,canonical_name,aliases FROM entities WHERE merged_into IS NULL AND id<>?",
                (entity["id"],),
            ).fetchall()
            for row in conflict:
                names = [row["canonical_name"]] + json.loads(row["aliases"])
                if any(normalize_name(name) == normalized for name in names):
                    raise DomainError("别名已属于其他实体，应先执行实体合并", 409)
            if alias not in aliases:
                aliases.append(alias)
                aliases.sort(key=str.casefold)
            conn.execute(
                "UPDATE entities SET aliases=?,version=version+1,updated_at=? WHERE id=? AND version=?",
                (json.dumps(aliases, ensure_ascii=False), utcnow(), entity["id"], expected_version),
            )
            self._audit(conn, actor, "entity.alias_added", {"alias": alias}, entity["id"])
            return dict(conn.execute("SELECT * FROM entities WHERE id=?", (entity["id"],)).fetchone())

    def create_customer(self, actor: str, role: str, entity_id: int, customer_no: str,
                        country: str, occupation: str = "", allowlisted: bool = False,
                        risk_score: float = 0.0) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"analyst", "supervisor"}, "建立客户档案")
        try:
            risk_score = float(risk_score)
        except (TypeError, ValueError) as exc:
            raise DomainError("风险评分必须是数值") from exc
        if not customer_no.strip() or len(country.strip()) != 2 or not 0 <= risk_score <= 1:
            raise DomainError("客户编号、国家代码或风险评分无效")
        with self.connect() as conn:
            entity = self._resolve_entity(conn, entity_id)
            try:
                cur = conn.execute(
                    """INSERT INTO customers(entity_id,customer_no,country,occupation,allowlisted,risk_score,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (entity["id"], customer_no.strip(), country.strip().upper(), occupation.strip(), int(bool(allowlisted)), risk_score, utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("客户编号已存在", 409) from exc
            self._audit(conn, actor, "customer.created", {"customer_no": customer_no.strip()}, entity["id"])
            return dict(conn.execute("SELECT * FROM customers WHERE id=?", (cur.lastrowid,)).fetchone())

    @staticmethod
    def _canonical_entries(entries: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        clean: dict[str, dict[str, Any]] = {}
        for raw in entries or []:
            name = str(raw.get("name", "")).strip()
            normalized = normalize_name(name)
            if not normalized:
                raise DomainError("名单条目名称不能为空")
            countries = sorted({str(c).strip().upper() for c in (raw.get("countries") or []) if str(c).strip()})
            if normalized in clean:
                raise DomainError("同批次内存在重复名单条目：%s" % name, 409)
            clean[normalized] = {"name": name, "normalized_name": normalized, "countries": countries}
        return [clean[k] for k in sorted(clean)]

    @staticmethod
    def _entries_hash(list_name: str, entries: list[dict[str, Any]]) -> str:
        payload = [
            [e["normalized_name"], e["countries"]]
            for e in sorted(entries, key=lambda item: item["normalized_name"])
        ]
        digest = hashlib.sha256(
            json.dumps([list_name, payload], ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return "sha256:" + digest

    def _publish_snapshot(self, conn: sqlite3.Connection, list_name: str,
                          entries: list[dict[str, Any]], actor: str,
                          note: str = "", origin: str = "published") -> dict[str, Any]:
        """在调用方事务内发布不可变快照；批次头与条目同生共死，提交即整体可见。"""
        list_name = list_name.strip()
        if not list_name:
            raise DomainError("名单名称不能为空")
        entries = self._canonical_entries(entries)
        content_hash = self._entries_hash(list_name, entries)
        duplicate = conn.execute(
            "SELECT version FROM watchlist_snapshots WHERE list_name=? AND content_hash=?",
            (list_name, content_hash),
        ).fetchone()
        if duplicate:
            raise DomainError("名单内容与第 %s 版完全相同，无需重复发布" % duplicate["version"], 409)
        row = conn.execute(
            "SELECT COALESCE(MAX(version),0) AS v FROM watchlist_snapshots WHERE list_name=?",
            (list_name,),
        ).fetchone()
        version = row["v"] + 1
        now = utcnow()
        cur = conn.execute(
            """INSERT INTO watchlist_snapshots(list_name,version,status,content_hash,entry_count,published_by,published_at,note,origin)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (list_name, version, "published", content_hash, len(entries), actor, now, note.strip(), origin),
        )
        snapshot_id = cur.lastrowid
        conn.executemany(
            """INSERT INTO watchlist_snapshot_entries(snapshot_id,list_name,version,seq,name,normalized_name,countries)
               VALUES(?,?,?,?,?,?,?)""",
            [
                (snapshot_id, list_name, version, seq, e["name"], e["normalized_name"],
                 json.dumps(e["countries"], ensure_ascii=False))
                for seq, e in enumerate(entries, start=1)
            ],
        )
        self._audit(
            conn, actor, "watchlist.snapshot_published",
            {"list_name": list_name, "version": version, "entry_count": len(entries),
             "snapshot_id": snapshot_id, "origin": origin, "note": note.strip()},
        )
        return dict(conn.execute("SELECT * FROM watchlist_snapshots WHERE id=?", (snapshot_id,)).fetchone())

    def publish_watchlist(self, actor: str, role: str, list_name: str,
                          entries: list[dict[str, Any]], note: str = "") -> dict[str, Any]:
        """主管按批次发布完整名单快照。发布与入账并发时由快照读点保证互不覆盖。"""
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "发布名单批次")
        entries = self._canonical_entries(entries)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            snapshot = self._publish_snapshot(conn, list_name, entries, actor, note)
            conn.execute("DELETE FROM watchlist WHERE list_name=?", (list_name.strip(),))
            conn.executemany(
                "INSERT INTO watchlist(list_name,name,normalized_name,countries,version,active,updated_by,updated_at) VALUES(?,?,?,?,1,1,?,?)",
                [(snapshot["list_name"], e["name"], e["normalized_name"],
                  json.dumps(e["countries"], ensure_ascii=False), actor, snapshot["published_at"])
                 for e in entries],
            )
            return snapshot

    def add_or_update_watchlist(self, actor: str, role: str, list_name: str, name: str,
                                countries: list[str] | None = None,
                                active: bool = True, expected_version: int | None = None) -> dict[str, Any]:
        """[兼容] 旧逐条维护：先写草稿表，再把整张名单作为不可变批次发布。

        expected_version 针对旧条目的版本号；停用条目会从下一版快照中移除。
        名单一旦以快照形式发布，依据只能通过新版本修正，不能改写历史版本。
        """
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "维护制裁名单")
        list_name, name = list_name.strip(), name.strip()
        normalized = normalize_name(name)
        countries_list = sorted({c.strip().upper() for c in (countries or []) if c.strip()})
        countries_json = json.dumps(countries_list, ensure_ascii=False)
        if not list_name or not normalized:
            raise DomainError("名单名称和实体名称不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM watchlist WHERE list_name=? AND normalized_name=?",
                (list_name, normalized),
            ).fetchone()
            if row:
                if expected_version is not None and row["version"] != int(expected_version):
                    raise DomainError("名单条目已变化，请刷新后重试", 409)
                conn.execute(
                    "UPDATE watchlist SET name=?,countries=?,active=?,version=version+1,updated_by=?,updated_at=? WHERE id=?",
                    (name, countries_json, int(bool(active)), actor, utcnow(), row["id"]),
                )
            else:
                conn.execute(
                    "INSERT INTO watchlist(list_name,name,normalized_name,countries,active,updated_by,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (list_name, name, normalized, countries_json, int(bool(active)), actor, utcnow()),
                )
            draft_rows = conn.execute(
                "SELECT name,countries FROM watchlist WHERE list_name=? AND active=1 ORDER BY normalized_name",
                (list_name,),
            ).fetchall()
            draft = [{"name": r["name"], "countries": json.loads(r["countries"])} for r in draft_rows]
            snapshot = None
            latest = conn.execute(
                "SELECT content_hash FROM watchlist_snapshots WHERE list_name=? ORDER BY version DESC LIMIT 1",
                (list_name,),
            ).fetchone()
            if latest is None or latest["content_hash"] != self._entries_hash(list_name, self._canonical_entries(draft)):
                snapshot = self._publish_snapshot(
                    conn, list_name, draft, actor, "逐条维护接口自动发布的批次", origin="incremental",
                )
                conn.execute(
                    "UPDATE watchlist SET version=? WHERE list_name=? AND active=1",
                    (snapshot["version"], list_name),
                )
            self._audit(conn, actor, "watchlist.updated",
                        {"list_name": list_name, "name": name, "active": active,
                         "snapshot_version": snapshot["version"] if snapshot else None})
            saved = conn.execute(
                "SELECT * FROM watchlist WHERE list_name=? AND normalized_name=?",
                (list_name, normalized),
            ).fetchone()
            return dict(saved) if saved else {"list_name": list_name, "name": name, "active": 0}

    @staticmethod
    def _match_entries(counterparty_name: str, country: str,
                       entries: list[sqlite3.Row | dict[str, Any]]) -> tuple[float, dict[str, Any] | None]:
        best_score, best = 0.0, None
        for row in entries:
            countries = json.loads(row["countries"])
            if countries and country.upper() not in countries:
                continue
            score = name_similarity(counterparty_name, row["name"])
            if score > best_score:
                best_score, best = score, row
        return best_score, best

    def _latest_snapshot(self, conn: sqlite3.Connection, list_name: str) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM watchlist_snapshots WHERE list_name=? AND status='published' ORDER BY version DESC LIMIT 1",
            (list_name,),
        ).fetchone()

    def _screen_with_baseline(self, conn: sqlite3.Connection, counterparty_name: str,
                              country: str) -> dict[str, Any]:
        """按每个名单当前最新的已发布快照筛查，并固化当时的版本依据。"""
        country = country.upper()
        lists = [r["list_name"] for r in conn.execute(
            "SELECT DISTINCT list_name FROM watchlist_snapshots WHERE status='published'"
        ).fetchall()]
        baseline: dict[str, int] = {}
        hits: list[dict[str, Any]] = []
        best_overall = 0.0
        best_hit: dict[str, Any] | None = None
        for list_name in lists:
            snapshot = self._latest_snapshot(conn, list_name)
            if snapshot is None:
                continue
            baseline[list_name] = snapshot["version"]
            entries = conn.execute(
                "SELECT * FROM watchlist_snapshot_entries WHERE snapshot_id=? ORDER BY seq",
                (snapshot["id"],),
            ).fetchall()
            score, match = self._match_entries(counterparty_name, country, entries)
            if match is None:
                continue
            hit = {
                "list_name": list_name,
                "snapshot_id": snapshot["id"],
                "snapshot_version": snapshot["version"],
                "entry_seq": match["seq"],
                "entry_name": match["name"],
                "countries": json.loads(match["countries"]),
                "score": round(score, 4),
            }
            hits.append(hit)
            if score > best_overall:
                best_overall, best_hit = score, hit
        detail = {
            "screened_at": utcnow(),
            "counterparty_name": counterparty_name,
            "counterparty_country": country,
            "baseline_versions": baseline,
            "hits": hits,
        }
        if best_hit is not None and best_overall >= 0.9:
            detail["match"] = best_hit
        return detail

    def ingest_transaction(self, actor: str, role: str, txn_ref: str, customer_id: int,
                           amount: float, currency: str, counterparty_name: str,
                           counterparty_country: str) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"analyst", "investigator"}, "录入交易")
        try:
            amount = float(amount)
        except (TypeError, ValueError) as exc:
            raise DomainError("交易金额必须是数值") from exc
        if not txn_ref.strip() or amount <= 0 or len(currency.strip()) != 3 or len(counterparty_country.strip()) != 2:
            raise DomainError("交易编号、金额、币种或国家代码无效")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            customer = conn.execute("SELECT * FROM customers WHERE id=?", (customer_id,)).fetchone()
            if not customer:
                raise DomainError("客户不存在", 404)
            entity = self._resolve_entity(conn, customer["entity_id"])
            country = counterparty_country.strip().upper()
            screen_detail = self._screen_with_baseline(conn, counterparty_name.strip(), country)
            match_detail = screen_detail.get("match")
            match_reason = "sanctions_match:%s:%s" % (match_detail["list_name"], match_detail["entry_name"]) if match_detail else None
            match_score = 0.95 if match_reason else 0.0
            base_risk = customer["risk_score"]
            reason = "normal"
            if match_reason:
                risk, reason = max(match_score, base_risk), match_reason
            elif country in HIGH_RISK_COUNTRIES:
                risk, reason = max(0.75, base_risk), "high_risk_country:" + country
            elif amount >= 100000:
                risk, reason = max(0.6, base_risk), "large_value_transaction"
            elif amount >= 50000:
                risk, reason = max(0.35, base_risk), "enhanced_review"
            else:
                risk = base_risk
            if entity["frozen"]:
                status = "blocked"
                reason = "frozen_entity"
                risk = 1.0
            elif match_reason:
                status = "escalated"
            elif risk >= 0.5:
                status = "review"
            else:
                status = "allowed"
            if customer["allowlisted"] and risk < 0.8 and amount <= 200000:
                status, risk, reason = "allowed", min(risk, 0.1), "allowlist_false_positive_reduction"
            try:
                cur = conn.execute(
                    """INSERT INTO transactions(txn_ref,customer_id,entity_id,amount,currency,counterparty_name,
                       counterparty_country,status,risk_score,reason,screen_snapshot_id,screen_detail,created_by,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (txn_ref.strip(), customer["id"], entity["id"], amount, currency.strip().upper(),
                     counterparty_name.strip(), country, status, risk, reason,
                     match_detail["snapshot_id"] if match_detail else None,
                     json.dumps(screen_detail, ensure_ascii=False, sort_keys=True), actor, utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("交易编号已存在", 409) from exc
            alert = None
            if status in {"review", "escalated", "blocked"}:
                fingerprint = "%s|%s|%s" % (entity["id"], reason.split(":")[0], normalize_name(counterparty_name))
                existing = conn.execute("SELECT * FROM alerts WHERE fingerprint=?", (fingerprint,)).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE alerts SET occurrences=occurrences+1,last_seen=?,risk_score=MAX(risk_score,?),transaction_id=? WHERE id=?",
                        (utcnow(), risk, cur.lastrowid, existing["id"]),
                    )
                    alert_id = existing["id"]
                else:
                    alert_cur = conn.execute(
                        """INSERT INTO alerts(fingerprint,entity_id,transaction_id,reason,risk_score,first_seen,last_seen)
                           VALUES(?,?,?,?,?,?,?)""",
                        (fingerprint, entity["id"], cur.lastrowid, reason, risk, utcnow(), utcnow()),
                    )
                    alert_id = alert_cur.lastrowid
                alert = dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
            if entity["frozen"]:
                conn.execute("UPDATE transactions SET status='blocked' WHERE entity_id=? AND status='review'", (entity["id"],))
            self._audit(conn, actor, "transaction.ingested", {"txn_ref": txn_ref, "status": status, "reason": reason}, entity["id"])
            transaction = dict(conn.execute("SELECT * FROM transactions WHERE id=?", (cur.lastrowid,)).fetchone())
            return {"transaction": transaction, "alert": alert, "resolved_entity_id": entity["id"]}

    def run_night_review(self, actor: str, role: str, list_name: str | None = None,
                         limit: int = 1000) -> dict[str, Any]:
        """用最新快照重筛历史交易：原交易和原线索一律不改，只生成/撤销待办。"""
        actor = clean_actor(actor)
        require_role(role, {"supervisor", "director"}, "执行夜间复核")
        try:
            limit = max(1, min(int(limit), 10000))
        except (TypeError, ValueError) as exc:
            raise DomainError("复核批量上限无效") from exc
        created, revoked, unchanged, skipped = [], [], 0, 0
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            params: list[Any] = []
            where = "status='published'"
            if list_name:
                where += " AND list_name=?"
                params.append(list_name.strip())
            snapshots = conn.execute(
                "SELECT * FROM watchlist_snapshots WHERE %s ORDER BY published_at DESC, id DESC" % where,
                params,
            ).fetchall()
            latest_by_list: dict[str, sqlite3.Row] = {}
            for snap in snapshots:
                latest_by_list.setdefault(snap["list_name"], snap)
            if list_name and not latest_by_list:
                raise DomainError("名单不存在或尚无已发布快照", 404)
            txns = conn.execute(
                "SELECT * FROM transactions ORDER BY id LIMIT ?", (limit,),
            ).fetchall()
            now = utcnow()
            for txn in txns:
                detail = json.loads(txn["screen_detail"] or "{}")
                baseline = detail.get("baseline_versions", {})
                old_hits = {h["list_name"]: h for h in detail.get("hits", [])}
                for current_list, snap in latest_by_list.items():
                    old_version = baseline.get(current_list)
                    if old_version == snap["version"]:
                        continue
                    entries = conn.execute(
                        "SELECT * FROM watchlist_snapshot_entries WHERE snapshot_id=? ORDER BY seq",
                        (snap["id"],),
                    ).fetchall()
                    score, match = self._match_entries(
                        txn["counterparty_name"], txn["counterparty_country"], entries,
                    )
                    old_hit = old_hits.get(current_list)
                    old_match = old_hit if old_hit and old_hit.get("score", 0) >= 0.9 else None
                    new_match = match if match is not None and score >= 0.9 else None
                    if old_match and new_match and old_match["entry_name"] == new_match["name"] \
                            and old_match["snapshot_version"] == snap["version"]:
                        unchanged += 1
                        continue
                    if not old_match and not new_match:
                        continue
                    # 该交易在该名单下被更新版本取代的未决待办先撤销，再生成当前待办。
                    open_tasks = conn.execute(
                        """SELECT * FROM review_tasks WHERE transaction_id=? AND list_name=?
                           AND status='open' AND new_snapshot_id<>?""",
                        (txn["id"], current_list, snap["id"]),
                    ).fetchall()
                    superseded_id: int | None = None
                    for task in open_tasks:
                        conn.execute(
                            "UPDATE review_tasks SET status='revoked',resolved_at=? WHERE id=?",
                            (now, task["id"]),
                        )
                        revoked.append(task["id"])
                        superseded_id = task["id"]
                    existing = conn.execute(
                        "SELECT id FROM review_tasks WHERE transaction_id=? AND new_snapshot_id=?",
                        (txn["id"], snap["id"]),
                    ).fetchone()
                    if existing:
                        continue
                    if new_match and not old_match:
                        change_type = "new_hit"
                        change_detail = {"new": {"entry_name": new_match["name"], "entry_seq": new_match["seq"],
                                                 "score": round(score, 4)}}
                    elif old_match and not new_match:
                        change_type = "hit_cleared"
                        change_detail = {"old": {"entry_name": old_match["entry_name"],
                                                 "snapshot_version": old_match["snapshot_version"],
                                                 "score": old_match["score"]}}
                    else:
                        change_type = "hit_changed"
                        change_detail = {
                            "old": {"entry_name": old_match["entry_name"],
                                    "snapshot_version": old_match["snapshot_version"],
                                    "score": old_match["score"]},
                            "new": {"entry_name": new_match["name"], "entry_seq": new_match["seq"],
                                    "score": round(score, 4)},
                        }
                    task_detail = {
                        "txn_ref": txn["txn_ref"],
                        "counterparty_name": txn["counterparty_name"],
                        "counterparty_country": txn["counterparty_country"],
                        "old_version": old_version,
                        "new_version": snap["version"],
                        **change_detail,
                    }
                    cur = conn.execute(
                        """INSERT INTO review_tasks(transaction_id,list_name,old_snapshot_id,new_snapshot_id,
                           change_type,detail,superseded_task_id,created_at)
                           VALUES(?,?,?,?,?,?,?,?)""",
                        (txn["id"], current_list,
                         old_hit["snapshot_id"] if old_hit else None,
                         snap["id"], change_type,
                         json.dumps(task_detail, ensure_ascii=False, sort_keys=True),
                         superseded_id, now),
                    )
                    created.append({"task_id": cur.lastrowid, "txn_id": txn["id"],
                                    "list_name": current_list, "change_type": change_type})
            self._audit(conn, actor, "watchlist.night_review",
                        {"list_name": list_name, "created": len(created),
                         "revoked": len(revoked)})
            return {"created": created, "revoked": revoked, "unchanged": unchanged,
                    "skipped": skipped, "reviewed_transactions": len(txns)}

    def resolve_review_task(self, actor: str, role: str, task_id: int, decision: str,
                            note: str) -> dict[str, Any]:
        """处置复核待办：可关闭/可转案件；已有案件只追加复核记录，绝不回写原交易或原线索。"""
        actor = clean_actor(actor)
        require_role(role, {"investigator", "supervisor"}, "处置复核待办")
        if decision not in {"confirm", "dismiss", "escalate"}:
            raise DomainError("复核决定无效（confirm/dismiss/escalate）")
        if not note.strip():
            raise DomainError("复核说明不能为空", 409)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            task = conn.execute("SELECT * FROM review_tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise DomainError("复核待办不存在", 404)
            if task["status"] != "open":
                raise DomainError("复核待办已处理或已撤销", 409)
            txn = conn.execute("SELECT * FROM transactions WHERE id=?", (task["transaction_id"],)).fetchone()
            case = conn.execute(
                "SELECT * FROM cases WHERE id=(SELECT case_id FROM alerts WHERE transaction_id=?)",
                (task["transaction_id"],),
            ).fetchone()
            if case is None:
                case = conn.execute(
                    "SELECT c.* FROM cases c JOIN alerts a ON a.case_id=c.id "
                    "WHERE a.entity_id=? ORDER BY c.id DESC LIMIT 1",
                    (txn["entity_id"],),
                ).fetchone()
            if case is not None:
                self._case_access(actor, role, case)
            detail = json.loads(task["detail"])
            resolution = {"decision": decision, "note": note.strip()}
            now = utcnow()
            new_case = None
            if decision == "escalate" and case is None:
                case_no = "RVW-%06d" % task_id
                cur = conn.execute(
                    """INSERT INTO cases(case_no,entity_id,alert_id,status,risk_score,assignee,created_by,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (case_no, txn["entity_id"], None,
                     0.95 if task["change_type"] != "hit_cleared" else txn["risk_score"],
                     actor, actor, now, now, now),
                )
                case = conn.execute("SELECT * FROM cases WHERE id=?", (cur.lastrowid,)).fetchone()
                new_case = dict(case)
                self._audit(conn, actor, "case.created_from_review",
                            {"case_no": case_no, "task_id": task_id}, txn["entity_id"], case["id"])
            status = {"confirm": "confirmed", "dismiss": "dismissed", "escalate": "escalated"}[decision]
            conn.execute(
                "UPDATE review_tasks SET status=?,resolution=?,resolved_by=?,resolved_at=? WHERE id=?",
                (status, json.dumps(resolution, ensure_ascii=False), actor, now, task_id),
            )
            review_id = None
            if case is not None:
                rc = conn.execute(
                    """INSERT INTO case_reviews(case_id,task_id,transaction_id,list_name,old_snapshot_id,
                       new_snapshot_id,change_type,detail,actor,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (case["id"], task_id, txn["id"], task["list_name"], task["old_snapshot_id"],
                     task["new_snapshot_id"], task["change_type"],
                     json.dumps({"resolution": resolution, "change": detail}, ensure_ascii=False, sort_keys=True),
                     actor, now),
                )
                review_id = rc.lastrowid
                conn.execute("INSERT INTO case_notes(case_id,actor,note,created_at) VALUES(?,?,?,?)",
                             (case["id"], actor, "名单复核[%s/%s]：%s" % (task["list_name"], task["change_type"], note.strip()), now))
                self._audit(conn, actor, "case.review_appended",
                            {"task_id": task_id, "change_type": task["change_type"], "decision": decision},
                            case["entity_id"], case["id"])
            else:
                self._audit(conn, actor, "review_task.resolved",
                            {"task_id": task_id, "decision": decision})
            return {
                "task": dict(conn.execute("SELECT * FROM review_tasks WHERE id=?", (task_id,)).fetchone()),
                "case_id": case["id"] if case is not None else None,
                "case": new_case,
                "case_review_id": review_id,
            }

    def triage_alert(self, actor: str, role: str, alert_id: int, decision: str,
                    assignee: str | None = None, case_no: str | None = None,
                    reason: str = "") -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"investigator", "supervisor"}, "处置可疑线索")
        if decision not in {"dismiss", "escalate"}:
            raise DomainError("线索处置决定无效")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            alert = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if not alert:
                raise DomainError("线索不存在", 404)
            if alert["status"] not in {"new", "triaged"}:
                raise DomainError("线索已处置", 409)
            if decision == "dismiss":
                if not reason.strip():
                    raise DomainError("误报关闭必须填写理由", 409)
                if alert["risk_score"] >= 0.9:
                    raise DomainError("制裁命中线索不能直接关闭", 409)
                conn.execute("UPDATE alerts SET status='dismissed',dismissed_reason=? WHERE id=?", (reason.strip(), alert_id))
                self._audit(conn, actor, "alert.dismissed", {"alert_id": alert_id, "reason": reason.strip()}, alert["entity_id"])
                return {"alert": dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()), "case": None}
            number = (case_no or "CASE-%06d" % alert_id).strip()
            try:
                cur = conn.execute(
                    """INSERT INTO cases(case_no,entity_id,alert_id,status,risk_score,assignee,created_by,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (number, alert["entity_id"], alert_id, "investigating", alert["risk_score"], (assignee or actor).strip(), actor, utcnow(), utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("案件编号已存在", 409) from exc
            conn.execute("UPDATE alerts SET status='case_created',case_id=? WHERE id=?", (cur.lastrowid, alert_id))
            self._audit(conn, actor, "case.created", {"case_no": number, "alert_id": alert_id}, alert["entity_id"], cur.lastrowid)
            return {
                "alert": dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()),
                "case": dict(conn.execute("SELECT * FROM cases WHERE id=?", (cur.lastrowid,)).fetchone()),
            }

    def _case_access(self, actor: str, role: str, case: sqlite3.Row) -> None:
        if role in {"supervisor", "director", "auditor"}:
            return
        if role == "investigator" and case["assignee"] == actor:
            return
        raise DomainError("案件仅限被指派的调查人员或授权角色访问", 403)

    def update_case(self, actor: str, role: str, case_id: int, note: str,
                    expected_version: int, status: str | None = None,
                    assignee: str | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"investigator", "supervisor"}, "更新案件")
        if not note.strip():
            raise DomainError("调查记录不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                raise DomainError("案件不存在", 404)
            self._case_access(actor, role, case)
            if case["version"] != int(expected_version):
                raise DomainError("案件已变化，请刷新后重试", 409)
            if case["status"] in {"closed", "report_filed"} and role != "supervisor":
                raise DomainError("已结束案件不能再更新", 409)
            new_status = status or case["status"]
            if new_status not in {"open", "investigating", "escalated", "closed", "report_filed"}:
                raise DomainError("案件状态无效")
            if role == "investigator" and new_status in {"closed", "report_filed"}:
                raise DomainError("调查员不能自行结束案件", 403)
            conn.execute("INSERT INTO case_notes(case_id,actor,note,created_at) VALUES(?,?,?,?)", (case_id, actor, note.strip(), utcnow()))
            conn.execute(
                "UPDATE cases SET status=?,assignee=COALESCE(?,assignee),version=version+1,updated_at=? WHERE id=? AND version=?",
                (new_status, assignee.strip() if assignee else None, utcnow(), case_id, expected_version),
            )
            self._audit(conn, actor, "case.updated", {"status": new_status, "note": note.strip()}, case["entity_id"], case_id)
            return dict(conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone())

    def freeze_entity(self, actor: str, role: str, entity_id: int, reason: str,
                      expected_version: int, case_id: int | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor", "director"}, "冻结实体")
        if not reason.strip():
            raise DomainError("冻结原因不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            entity = self._resolve_entity(conn, entity_id)
            if entity["version"] != int(expected_version):
                raise DomainError("实体已变化，请刷新后重试", 409)
            conn.execute("UPDATE entities SET frozen=1,risk_level='high',version=version+1,updated_at=? WHERE id=?", (utcnow(), entity["id"]))
            conn.execute("UPDATE transactions SET status='blocked' WHERE entity_id=? AND status IN ('review','allowed')", (entity["id"],))
            if case_id is not None:
                case = conn.execute("SELECT * FROM cases WHERE id=? AND entity_id=?", (case_id, entity["id"])).fetchone()
                if not case:
                    raise DomainError("案件与实体不匹配", 409)
                conn.execute(
                    "UPDATE cases SET freeze_target=1,status=CASE WHEN status='investigating' THEN 'escalated' ELSE status END,version=version+1,updated_at=? WHERE id=?",
                    (utcnow(), case_id),
                )
            self._audit(conn, actor, "entity.frozen", {"reason": reason.strip()}, entity["id"], case_id)
            return dict(conn.execute("SELECT * FROM entities WHERE id=?", (entity["id"],)).fetchone())

    def unfreeze_entity(self, actor: str, role: str, entity_id: int, reason: str,
                        expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"director"}, "解除冻结")
        if not reason.strip():
            raise DomainError("解冻原因不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            entity = self._resolve_entity(conn, entity_id)
            if entity["version"] != int(expected_version):
                raise DomainError("实体已变化，请刷新后重试", 409)
            conn.execute("UPDATE entities SET frozen=0,risk_level='medium',version=version+1,updated_at=? WHERE id=?", (utcnow(), entity["id"]))
            self._audit(conn, actor, "entity.unfrozen", {"reason": reason.strip()}, entity["id"])
            return dict(conn.execute("SELECT * FROM entities WHERE id=?", (entity["id"],)).fetchone())

    def merge_entities(self, actor: str, role: str, source_id: int, target_id: int,
                       source_version: int, target_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "合并实体")
        if source_id == target_id:
            raise DomainError("不能合并同一实体")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            source = self._resolve_entity(conn, source_id)
            target = self._resolve_entity(conn, target_id)
            if source["version"] != int(source_version) or target["version"] != int(target_version):
                raise DomainError("实体已变化，请刷新后重试", 409)
            if source["id"] == target["id"]:
                raise DomainError("实体已经合并到目标", 409)
            source_aliases = json.loads(source["aliases"])
            target_aliases = json.loads(target["aliases"])
            aliases = sorted(set(target_aliases + source_aliases + [source["canonical_name"]]), key=str.casefold)
            now = utcnow()
            conn.execute(
                """UPDATE entities SET aliases=?,frozen=MAX(frozen,?),risk_level=?,version=version+1,updated_at=?
                   WHERE id=?""",
                (json.dumps(aliases, ensure_ascii=False), source["frozen"],
                 "high" if source["frozen"] or target["frozen"] else max(source["risk_level"], target["risk_level"], key=lambda x: {"low": 0, "medium": 1, "high": 2}.get(x, 0)),
                 now, target["id"]),
            )
            conn.execute("UPDATE entities SET merged_into=?,version=version+1,updated_at=? WHERE id=?", (target["id"], now, source["id"]))
            conn.execute("UPDATE customers SET entity_id=?,version=version+1 WHERE entity_id=? AND merged_into IS NULL", (target["id"], source["id"]))
            conn.execute("UPDATE transactions SET entity_id=? WHERE entity_id=?", (target["id"], source["id"]))
            conn.execute("UPDATE alerts SET entity_id=? WHERE entity_id=?", (target["id"], source["id"]))
            conn.execute("UPDATE cases SET entity_id=?,version=version+1,updated_at=? WHERE entity_id=?", (target["id"], now, source["id"]))
            details = {"source": source["canonical_name"], "target": target["canonical_name"], "aliases": aliases}
            conn.execute(
                "INSERT INTO entity_merges(source_id,target_id,actor,details,created_at) VALUES(?,?,?,?,?)",
                (source["id"], target["id"], actor, json.dumps(details, ensure_ascii=False), now),
            )
            self._audit(conn, actor, "entity.merged", details, target["id"])
            return {"source": dict(conn.execute("SELECT * FROM entities WHERE id=?", (source["id"],)).fetchone()),
                    "target": dict(conn.execute("SELECT * FROM entities WHERE id=?", (target["id"],)).fetchone())}

    def file_report(self, actor: str, role: str, case_id: int, report_ref: str,
                    expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "提交监管报告")
        if not report_ref.strip():
            raise DomainError("监管报告编号不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                raise DomainError("案件不存在", 404)
            if case["version"] != int(expected_version):
                raise DomainError("案件已变化，请刷新后重试", 409)
            if case["status"] not in {"investigating", "escalated"}:
                raise DomainError("当前案件状态不能提交监管报告", 409)
            if case["risk_score"] < 0.5:
                raise DomainError("低风险案件不需要监管报告", 409)
            conn.execute(
                "UPDATE cases SET status='report_filed',report_ref=?,version=version+1,updated_at=? WHERE id=?",
                (report_ref.strip(), utcnow(), case_id),
            )
            self._audit(conn, actor, "case.report_filed", {"report_ref": report_ref.strip()}, case["entity_id"], case_id)
            return dict(conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone())

    def get_case(self, actor: str, role: str, case_id: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        if role not in SENSITIVE_ROLES:
            raise DomainError("角色无权查看案件", 403)
        with self.connect() as conn:
            case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                raise DomainError("案件不存在", 404)
            self._case_access(actor, role, case)
            notes = [dict(r) for r in conn.execute("SELECT * FROM case_notes WHERE case_id=? ORDER BY id", (case_id,)).fetchall()]
            reviews = [dict(r) for r in conn.execute(
                "SELECT * FROM case_reviews WHERE case_id=? ORDER BY id", (case_id,)
            ).fetchall()]
            for row in reviews:
                row["detail"] = json.loads(row["detail"])
            return {"case": dict(case), "notes": notes, "reviews": reviews}

    def list_snapshots(self, actor: str, role: str, list_name: str | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        if role not in SENSITIVE_ROLES:
            raise DomainError("角色无权查看名单版本", 403)
        with self.connect() as conn:
            if list_name:
                rows = conn.execute(
                    "SELECT * FROM watchlist_snapshots WHERE list_name=? AND status='published' ORDER BY version",
                    (list_name,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM watchlist_snapshots WHERE status='published' ORDER BY list_name, version"
                ).fetchall()
            return {"snapshots": [dict(r) for r in rows]}

    def get_snapshot(self, actor: str, role: str, snapshot_id: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        if role not in SENSITIVE_ROLES:
            raise DomainError("角色无权查看名单版本", 403)
        with self.connect() as conn:
            snap = conn.execute("SELECT * FROM watchlist_snapshots WHERE id=?", (snapshot_id,)).fetchone()
            if not snap or snap["status"] != "published":
                raise DomainError("名单快照不存在", 404)
            entries = [dict(r) for r in conn.execute(
                "SELECT seq,name,countries FROM watchlist_snapshot_entries WHERE snapshot_id=? ORDER BY seq",
                (snapshot_id,),
            ).fetchall()]
            for entry in entries:
                entry["countries"] = json.loads(entry["countries"])
            return {"snapshot": dict(snap), "entries": entries}

    def list_review_tasks(self, actor: str, role: str, status_filter: str = "open") -> dict[str, Any]:
        actor = clean_actor(actor)
        if role not in SENSITIVE_ROLES:
            raise DomainError("角色无权查看复核待办", 403)
        if status_filter not in {"open", "all", "resolved"}:
            raise DomainError("待办过滤条件无效")
        with self.connect() as conn:
            if status_filter == "all":
                rows = conn.execute("SELECT * FROM review_tasks ORDER BY id DESC LIMIT 200").fetchall()
            elif status_filter == "resolved":
                rows = conn.execute(
                    "SELECT * FROM review_tasks WHERE status<>'open' ORDER BY id DESC LIMIT 200"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM review_tasks WHERE status='open' ORDER BY id DESC LIMIT 200"
                ).fetchall()
            tasks = [dict(r) for r in rows]
            for task in tasks:
                task["detail"] = json.loads(task["detail"])
                if task.get("resolution"):
                    task["resolution"] = json.loads(task["resolution"])
            return {"tasks": tasks}

    def state(self, actor: str = "", role: str = "viewer") -> dict[str, Any]:
        if role not in SENSITIVE_ROLES:
            return {"entities": [], "transactions": [], "alerts": [], "cases": [], "timeline": [], "access_limited": True}
        with self.connect() as conn:
            if role == "investigator":
                cases = [dict(r) for r in conn.execute("SELECT * FROM cases WHERE assignee=? ORDER BY id DESC", (actor,)).fetchall()]
            else:
                cases = [dict(r) for r in conn.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()]
            entities = [dict(r) for r in conn.execute("SELECT * FROM entities ORDER BY id DESC LIMIT 100").fetchall()]
            transactions = [dict(r) for r in conn.execute("SELECT * FROM transactions ORDER BY id DESC LIMIT 100").fetchall()]
            case_ids = [c["id"] for c in cases]
            if role == "investigator" and case_ids:
                marks = ",".join("?" for _ in case_ids)
                alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts WHERE case_id IN (%s) ORDER BY id DESC LIMIT 100" % marks, case_ids).fetchall()]
            elif role == "investigator":
                alerts = []
            else:
                alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100").fetchall()]
            timeline = [dict(r) for r in conn.execute("SELECT * FROM timeline ORDER BY id DESC LIMIT 200").fetchall()]
            snapshots = [dict(r) for r in conn.execute(
                "SELECT * FROM watchlist_snapshots WHERE status='published' ORDER BY id DESC LIMIT 50"
            ).fetchall()]
            review_tasks = [dict(r) for r in conn.execute(
                "SELECT * FROM review_tasks ORDER BY id DESC LIMIT 100"
            ).fetchall()]
            for task in review_tasks:
                task["detail"] = json.loads(task["detail"])
            for row in transactions:
                row["screen_detail"] = json.loads(row["screen_detail"] or "{}")
        return {"entities": entities, "transactions": transactions, "alerts": alerts,
                "cases": cases, "timeline": timeline, "snapshots": snapshots,
                "review_tasks": review_tasks, "access_limited": False}

    def seed_demo(self) -> dict[str, Any]:
        with self.connect() as conn:
            if conn.execute("SELECT COUNT(*) AS c FROM entities").fetchone()["c"]:
                return {"seeded": False, "reason": "已有数据"}
        entity = self.create_entity("analyst-demo", "analyst", "organization", "海岳贸易有限公司", ["海岳贸易"])
        customer = self.create_customer("analyst-demo", "analyst", entity["id"], "CUST-0001", "CN", "贸易", False, 0.2)
        snapshot = self.publish_watchlist(
            "sup-demo", "supervisor", "OFAC",
            [{"name": "海岳贸易有限公司", "countries": ["CN"]}],
            note="演示名单第一版",
        )
        result = self.ingest_transaction("analyst-demo", "analyst", "TXN-DEMO-0001", customer["id"], 150000, "USD", "海岳贸易有限公司", "CN")
        return {"seeded": True, "entity_id": entity["id"], "customer_id": customer["id"],
                "alert_id": result["alert"]["id"] if result["alert"] else None,
                "snapshot_version": snapshot["version"]}


class ApiHandler(BaseHTTPRequestHandler):
    service: FinancialCrimeService

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _headers(self) -> tuple[str, str]:
        return self.headers.get("X-User", ""), self.headers.get("X-Role", "viewer")

    def _json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 2_000_000:
            raise DomainError("请求体过大", 413)
        if not length:
            return {}
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DomainError("请求体不是有效 JSON") from exc
        if not isinstance(value, dict):
            raise DomainError("JSON 请求体必须是对象")
        return value

    def do_GET(self) -> None:
        try:
            path = urlparse(self.path).path
            if path in {"/", "/index.html"}:
                body = (ROOT / "static" / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            actor, role = self._headers()
            if path == "/health":
                self._send(200, {"status": "ok", "service": "financial-crime"})
            elif path == "/api/state":
                self._send(200, self.service.state(actor, role))
            elif path == "/api/snapshots":
                query = urlparse(self.path).query
                list_name = None
                if query:
                    from urllib.parse import parse_qs
                    parsed = parse_qs(query)
                    list_name = parsed.get("list_name", [None])[0]
                self._send(200, self.service.list_snapshots(actor, role, list_name))
            elif path.startswith("/api/snapshots/"):
                self._send(200, self.service.get_snapshot(actor, role, int(path.split("/")[3])))
            elif path == "/api/reviews":
                query = urlparse(self.path).query
                status_filter = "open"
                if query:
                    from urllib.parse import parse_qs
                    status_filter = parse_qs(query).get("status", ["open"])[0]
                self._send(200, self.service.list_review_tasks(actor, role, status_filter))
            elif path.startswith("/api/cases/"):
                self._send(200, self.service.get_case(actor, role, int(path.split("/")[3])))
            else:
                self._send(404, {"error": "接口不存在"})
        except DomainError as exc:
            self._send(exc.status, {"error": str(exc)})
        except (ValueError, IndexError) as exc:
            self._send(400, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            path, data, (actor, role) = urlparse(self.path).path, self._json(), self._headers()
            if path == "/api/entities":
                result = self.service.create_entity(actor, role, **data)
            elif path == "/api/entities/alias":
                result = self.service.add_alias(actor, role, **data)
            elif path == "/api/customers":
                result = self.service.create_customer(actor, role, **data)
            elif path == "/api/watchlist":
                result = self.service.add_or_update_watchlist(actor, role, **data)
            elif path == "/api/watchlist/publish":
                result = self.service.publish_watchlist(actor, role, **data)
            elif path == "/api/reviews/night-run":
                result = self.service.run_night_review(actor, role, **data)
            elif path == "/api/reviews/resolve":
                result = self.service.resolve_review_task(actor, role, **data)
            elif path == "/api/transactions":
                result = self.service.ingest_transaction(actor, role, **data)
            elif path == "/api/alerts/triage":
                result = self.service.triage_alert(actor, role, **data)
            elif path == "/api/cases/update":
                result = self.service.update_case(actor, role, **data)
            elif path == "/api/entities/freeze":
                result = self.service.freeze_entity(actor, role, **data)
            elif path == "/api/entities/unfreeze":
                result = self.service.unfreeze_entity(actor, role, **data)
            elif path == "/api/entities/merge":
                result = self.service.merge_entities(actor, role, **data)
            elif path == "/api/cases/report":
                result = self.service.file_report(actor, role, **data)
            else:
                raise DomainError("接口不存在", 404)
            self._send(201, result)
        except DomainError as exc:
            self._send(exc.status, {"error": str(exc)})
        except (KeyError, TypeError, ValueError) as exc:
            self._send(400, {"error": "请求参数错误: %s" % exc})
        except Exception as exc:
            self._send(500, {"error": "服务器内部错误", "detail": str(exc)})

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def serve(service: FinancialCrimeService, host: str, port: int) -> None:
    ApiHandler.service = service
    server = ThreadingHTTPServer((host, port), ApiHandler)
    print("Financial crime service listening on http://%s:%s" % (host, port))
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="金融犯罪调查与制裁筛查服务")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8208)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    service = FinancialCrimeService(args.db)
    if args.init:
        print(json.dumps(service.seed_demo() if args.seed else {"initialized": True, "db": args.db}, ensure_ascii=False))
        return
    serve(service, args.host, args.port)


if __name__ == "__main__":
    main()
