"""Financial-crime investigation and sanctions-screening service."""
from __future__ import annotations

import argparse
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
                    snapshot_no TEXT NOT NULL UNIQUE,
                    list_name TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    entry_count INTEGER NOT NULL,
                    checksum TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    note TEXT NOT NULL DEFAULT '',
                    published_by TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    UNIQUE(list_name, version)
                );
                CREATE TABLE IF NOT EXISTS watchlist_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL REFERENCES watchlist_snapshots(id),
                    list_name TEXT NOT NULL,
                    name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL,
                    countries TEXT NOT NULL DEFAULT '[]',
                    entry_ref TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS review_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_no TEXT NOT NULL UNIQUE,
                    transaction_id INTEGER NOT NULL REFERENCES transactions(id),
                    snapshot_id INTEGER NOT NULL REFERENCES watchlist_snapshots(id),
                    snapshot_version INTEGER NOT NULL,
                    list_name TEXT NOT NULL,
                    entry_id INTEGER NOT NULL REFERENCES watchlist_entries(id),
                    entry_name TEXT NOT NULL,
                    match_score REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    reason TEXT NOT NULL DEFAULT '',
                    case_id INTEGER REFERENCES cases(id),
                    created_at TEXT NOT NULL,
                    revoked_by TEXT,
                    revoked_at TEXT,
                    revoke_reason TEXT,
                    completed_at TEXT,
                    UNIQUE(transaction_id, snapshot_id)
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
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    screened_snapshot_id INTEGER REFERENCES watchlist_snapshots(id),
                    match_snapshot_id INTEGER REFERENCES watchlist_snapshots(id),
                    match_entry_id INTEGER REFERENCES watchlist_entries(id),
                    match_details TEXT
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
                    last_seen TEXT NOT NULL,
                    snapshot_id INTEGER REFERENCES watchlist_snapshots(id),
                    match_details TEXT
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
                CREATE INDEX IF NOT EXISTS idx_watchlist_entries_snapshot ON watchlist_entries(snapshot_id);
                CREATE INDEX IF NOT EXISTS idx_watchlist_snapshots_list ON watchlist_snapshots(list_name, version DESC);
                CREATE INDEX IF NOT EXISTS idx_review_tasks_status ON review_tasks(status, created_at);
                """
            )
            self._ensure_columns(conn, "transactions", {
                "screened_snapshot_id": "INTEGER REFERENCES watchlist_snapshots(id)",
                "match_snapshot_id": "INTEGER REFERENCES watchlist_snapshots(id)",
                "match_entry_id": "INTEGER REFERENCES watchlist_entries(id)",
                "match_details": "TEXT",
            })
            self._ensure_columns(conn, "alerts", {
                "snapshot_id": "INTEGER REFERENCES watchlist_snapshots(id)",
                "match_details": "TEXT",
            })
            self._migrate_legacy_watchlist(conn)

    @staticmethod
    def _ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(%s)" % table)}
        for name, ddl in columns.items():
            if name not in existing:
                conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, name, ddl))

    @staticmethod
    def _checksum_entries(entries: list[tuple[str, str, list[str], str]]) -> str:
        import hashlib
        lines = []
        for name, normalized, countries, ref in sorted(entries, key=lambda item: item[1]):
            lines.append("%s|%s|%s" % (normalized, ",".join(countries), ref))
        return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()[:16]

    def _migrate_legacy_watchlist(self, conn: sqlite3.Connection) -> None:
        """旧的逐条名单迁移为第一版不可变历史快照。"""
        if conn.execute("SELECT COUNT(*) AS c FROM watchlist_snapshots").fetchone()["c"]:
            return
        rows = conn.execute("SELECT * FROM watchlist WHERE active=1 ORDER BY list_name, id").fetchall()
        if not rows:
            return
        by_list: dict[str, list[sqlite3.Row]] = {}
        for row in rows:
            by_list.setdefault(row["list_name"], []).append(row)
        for list_name, list_rows in by_list.items():
            entries = []
            for row in list_rows:
                countries = json.loads(row["countries"])
                entries.append((row["name"], row["normalized_name"], countries, "legacy:%d" % row["id"]))
            self._insert_snapshot(
                conn, list_name, entries,
                actor="system-migration",
                note="旧逐条名单迁移为第一版历史快照",
                now=utcnow(),
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

    def _insert_snapshot(self, conn: sqlite3.Connection, list_name: str,
                         entries: list[tuple[str, str, list[str], str]], *,
                         actor: str, note: str, now: str,
                         expected_version: int | None = None) -> dict[str, Any]:
        """在单一事务内写入不可变快照头与全部条目；失败整体回滚，不留半成品批次。"""
        row = conn.execute(
            "SELECT COALESCE(MAX(version),0) AS v FROM watchlist_snapshots WHERE list_name=?",
            (list_name,),
        ).fetchone()
        next_version = row["v"] + 1
        if expected_version is not None and int(expected_version) != row["v"]:
            raise DomainError("名单版本已变化，请刷新后重试", 409)
        checksum = self._checksum_entries(entries)
        snapshot_no = "%s-SNAP-%04d" % (re.sub(r"[^A-Z0-9]+", "_", list_name.upper()).strip("_"), next_version)
        cur = conn.execute(
            """INSERT INTO watchlist_snapshots(snapshot_no,list_name,version,entry_count,checksum,status,note,published_by,published_at)
               VALUES(?,?,?,?,?, 'active', ?, ?, ?)""",
            (snapshot_no, list_name, next_version, len(entries), checksum, note, actor, now),
        )
        snap_id = cur.lastrowid
        conn.executemany(
            """INSERT INTO watchlist_entries(snapshot_id,list_name,name,normalized_name,countries,entry_ref,created_at)
               VALUES(?,?,?,?,?,?,?)""",
            [
                (snap_id, list_name, name, normalized, json.dumps(clist, ensure_ascii=False), ref, now)
                for (name, normalized, clist, ref) in entries
            ],
        )
        return self._get_snapshot(conn, snap_id)

    @staticmethod
    def _get_snapshot(conn: sqlite3.Connection, snap_id: int) -> dict[str, Any]:
        snap = conn.execute("SELECT * FROM watchlist_snapshots WHERE id=?", (snap_id,)).fetchone()
        if not snap:
            raise DomainError("名单快照不存在", 404)
        data = dict(snap)
        data["entries"] = [dict(r) for r in conn.execute(
            "SELECT * FROM watchlist_entries WHERE snapshot_id=? ORDER BY id", (snap_id,)
        ).fetchall()]
        return data

    @staticmethod
    def _latest_snapshot(conn: sqlite3.Connection, list_name: str) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM watchlist_snapshots WHERE list_name=? ORDER BY version DESC, id DESC LIMIT 1",
            (list_name,),
        ).fetchone()

    @staticmethod
    def _latest_snapshot_ids(conn: sqlite3.Connection) -> list[tuple[str, int]]:
        rows = conn.execute(
            """SELECT s.list_name AS list_name, s.id AS id
               FROM watchlist_snapshots s
               JOIN (SELECT list_name, MAX(version) AS v FROM watchlist_snapshots GROUP BY list_name) m
                 ON s.list_name=m.list_name AND s.version=m.v"""
        ).fetchall()
        return [(r["list_name"], r["id"]) for r in rows]

    def publish_watchlist_snapshot(self, actor: str, role: str, list_name: str,
                                   entries: list[dict[str, Any]], note: str = "",
                                   expected_version: int | None = None) -> dict[str, Any]:
        """按批次发布不可变名单快照；发布与入账并发时由 BEGIN IMMEDIATE 串行化，中断即回滚。"""
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "发布名单快照")
        list_name = list_name.strip()
        if not list_name:
            raise DomainError("名单名称不能为空")
        clean_entries: list[tuple[str, str, list[str], str]] = []
        seen: set[str] = set()
        for raw in entries:
            if isinstance(raw, str):
                name, countries, ref = raw, [], ""
            else:
                name = str(raw.get("name", ""))
                countries = raw.get("countries", []) or []
                ref = str(raw.get("entry_ref", "") or "")
            name = name.strip()
            normalized = normalize_name(name)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            clist = sorted({c.strip().upper() for c in countries if c.strip()})
            clean_entries.append((name, normalized, clist, ref.strip()))
        if not clean_entries:
            raise DomainError("快照没有有效条目")
        now = utcnow()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            snapshot = self._insert_snapshot(
                conn, list_name, clean_entries, actor=actor, note=note.strip(),
                now=now, expected_version=expected_version,
            )
            self._audit(conn, actor, "watchlist.snapshot_published", {
                "list_name": list_name, "version": snapshot["version"],
                "entry_count": snapshot["entry_count"], "checksum": snapshot["checksum"],
            })
            return snapshot

    def add_or_update_watchlist(self, actor: str, role: str, list_name: str, name: str,
                                countries: list[str] | None = None,
                                active: bool = True, expected_version: int | None = None) -> dict[str, Any]:
        """兼容旧的逐条维护入口：在底层按当前全量条目发布一个新的不可变快照版本。"""
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "维护制裁名单")
        list_name, name = list_name.strip(), name.strip()
        normalized = normalize_name(name)
        if not list_name or not normalized:
            raise DomainError("名单名称和实体名称不能为空")
        now = utcnow()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            snap = self._latest_snapshot(conn, list_name)
            entries: list[tuple[str, str, list[str], str]] = []
            if snap:
                for row in conn.execute("SELECT * FROM watchlist_entries WHERE snapshot_id=?", (snap["id"],)).fetchall():
                    entries.append((row["name"], row["normalized_name"], json.loads(row["countries"]), row["entry_ref"]))
            found = False
            for idx, (_, existing_norm, _, _) in enumerate(entries):
                if existing_norm == normalized:
                    if active:
                        entries[idx] = (name, normalized,
                                         sorted({c.strip().upper() for c in (countries or []) if c.strip()}),
                                         entries[idx][3])
                    else:
                        entries.pop(idx)
                    found = True
                    break
            if not found and active:
                entries.append((name, normalized,
                                sorted({c.strip().upper() for c in (countries or []) if c.strip()}), ""))
            snapshot = self._insert_snapshot(
                conn, list_name, entries, actor=actor,
                note="逐条维护入口发布", now=now, expected_version=expected_version,
            )
            self._audit(conn, actor, "watchlist.updated", {
                "list_name": list_name, "name": name, "active": active,
                "snapshot_version": snapshot["version"],
            })
            return {
                "list_name": list_name, "name": name, "normalized_name": normalized,
                "countries": json.dumps(sorted({c.strip().upper() for c in (countries or []) if c.strip()}), ensure_ascii=False),
                "active": 1 if active else 0, "version": snapshot["version"],
                "snapshot_id": snapshot["id"],
            }

    def list_snapshots(self, actor: str, role: str, list_name: str | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        if role not in SENSITIVE_ROLES:
            raise DomainError("角色无权查看名单快照", 403)
        with self.connect() as conn:
            if list_name:
                snaps = conn.execute(
                    "SELECT * FROM watchlist_snapshots WHERE list_name=? ORDER BY version DESC", (list_name.strip(),)
                ).fetchall()
            else:
                snaps = conn.execute("SELECT * FROM watchlist_snapshots ORDER BY id DESC").fetchall()
            result = []
            for snap in snaps:
                data = dict(snap)
                data["entries"] = [dict(r) for r in conn.execute(
                    "SELECT id,name,normalized_name,countries,entry_ref FROM watchlist_entries WHERE snapshot_id=? ORDER BY id",
                    (snap["id"],),
                ).fetchall()]
                result.append(data)
            return {"snapshots": result}

    def _screen(self, conn: sqlite3.Connection, counterparty_name: str,
                country: str) -> tuple[float, dict[str, Any] | None]:
        country = country.upper()
        best_score, best = 0.0, None
        for list_name, snap_id in self._latest_snapshot_ids(conn):
            entries = conn.execute("SELECT * FROM watchlist_entries WHERE snapshot_id=?", (snap_id,)).fetchall()
            for row in entries:
                ecountries = json.loads(row["countries"])
                if ecountries and country not in ecountries:
                    continue
                score = name_similarity(counterparty_name, row["name"])
                if score > best_score:
                    best_score, best = score, (list_name, snap_id, row)
        if best and best_score >= 0.9:
            list_name, snap_id, row = best
            snap = conn.execute("SELECT version FROM watchlist_snapshots WHERE id=?", (snap_id,)).fetchone()
            match = {
                "snapshot_id": snap_id,
                "snapshot_version": snap["version"],
                "list_name": list_name,
                "entry_id": row["id"],
                "entry_name": row["name"],
                "countries": json.loads(row["countries"]),
                "score": round(best_score, 4),
            }
            return 0.95, match
        return best_score, None

    @staticmethod
    def _screen_against_entries(entries: list[sqlite3.Row], counterparty_name: str,
                                country: str) -> tuple[float, sqlite3.Row | None, float]:
        country = country.upper()
        best_score, best = 0.0, None
        for row in entries:
            ecountries = json.loads(row["countries"])
            if ecountries and country not in ecountries:
                continue
            score = name_similarity(counterparty_name, row["name"])
            if score > best_score:
                best_score, best = score, row
        if best and best_score >= 0.9:
            return 0.95, best, best_score
        return best_score, None, best_score

    @staticmethod
    def _find_case_for_transaction(conn: sqlite3.Connection, transaction_id: int) -> sqlite3.Row | None:
        alert = conn.execute(
            "SELECT case_id FROM alerts WHERE transaction_id=? AND case_id IS NOT NULL ORDER BY id DESC LIMIT 1",
            (transaction_id,),
        ).fetchone()
        if alert and alert["case_id"]:
            return conn.execute("SELECT * FROM cases WHERE id=?", (alert["case_id"],)).fetchone()
        return None

    def run_nightly_review(self, actor: str, role: str, snapshot_id: int | None = None) -> dict[str, Any]:
        """夜间复核：用新快照重算历史交易，生成可撤销待办；不改写原交易/原线索，已有案件只追加复核记录。"""
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "执行夜间复核")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if snapshot_id is not None:
                snap = conn.execute("SELECT * FROM watchlist_snapshots WHERE id=?", (snapshot_id,)).fetchone()
            else:
                snap = conn.execute("SELECT * FROM watchlist_snapshots ORDER BY id DESC LIMIT 1").fetchone()
            if not snap:
                raise DomainError("没有可用于复核的名单快照", 404)
            entries = conn.execute("SELECT * FROM watchlist_entries WHERE snapshot_id=?", (snap["id"],)).fetchall()
            transactions = conn.execute("SELECT * FROM transactions ORDER BY id").fetchall()
            created_tasks: list[dict[str, Any]] = []
            appended_cases: list[dict[str, Any]] = []
            for txn in transactions:
                _, entry, score = self._screen_against_entries(entries, txn["counterparty_name"], txn["counterparty_country"])
                if not entry or score < 0.9:
                    continue
                recorded_norm = None
                if txn["match_details"]:
                    try:
                        recorded_norm = normalize_name(json.loads(txn["match_details"]).get("entry_name", ""))
                    except (ValueError, TypeError):
                        recorded_norm = None
                if recorded_norm and recorded_norm == entry["normalized_name"]:
                    continue  # 入账时已依据同一制裁实体命中，仅快照版本推进，不重复生成待办
                existing_case = self._find_case_for_transaction(conn, txn["id"])
                basis_note = (
                    "夜间复核：名单快照 %s 第 %d 版命中条目「%s」（相似度 %.2f）；"
                    "原入账依据为「%s」。请重新评估该交易。"
                    % (snap["list_name"], snap["version"], entry["name"], score, txn["reason"])
                )
                if existing_case:
                    conn.execute(
                        "INSERT INTO case_notes(case_id,actor,note,created_at) VALUES(?,?,?,?)",
                        (existing_case["id"], actor, basis_note, utcnow()),
                    )
                    appended_cases.append({"case_id": existing_case["id"], "transaction_id": txn["id"], "entry_name": entry["name"]})
                    continue
                dup = conn.execute(
                    "SELECT id FROM review_tasks WHERE transaction_id=? AND snapshot_id=?",
                    (txn["id"], snap["id"]),
                ).fetchone()
                if dup:
                    continue
                count = conn.execute("SELECT COUNT(*) AS c FROM review_tasks").fetchone()["c"]
                task_no = "REV-%06d" % (count + 1)
                cur = conn.execute(
                    """INSERT INTO review_tasks(task_no,transaction_id,snapshot_id,snapshot_version,list_name,
                       entry_id,entry_name,match_score,status,reason,created_at)
                       VALUES(?,?,?,?,?,?,?,?, 'open', ?, ?)""",
                    (task_no, txn["id"], snap["id"], snap["version"], snap["list_name"],
                     entry["id"], entry["name"], score, basis_note, utcnow()),
                )
                created_tasks.append(dict(conn.execute("SELECT * FROM review_tasks WHERE id=?", (cur.lastrowid,)).fetchone()))
            self._audit(conn, actor, "watchlist.nightly_review", {
                "snapshot_id": snap["id"], "snapshot_version": snap["version"],
                "tasks_created": len(created_tasks), "cases_appended": len(appended_cases),
            })
            return {
                "snapshot": dict(snap),
                "tasks_created": created_tasks,
                "cases_appended": appended_cases,
            }

    def revoke_review_task(self, actor: str, role: str, task_id: int, reason: str) -> dict[str, Any]:
        """撤销夜间复核生成的待办；不影响原交易与原线索。"""
        actor = clean_actor(actor)
        require_role(role, {"supervisor", "investigator"}, "撤销复核待办")
        if not reason.strip():
            raise DomainError("撤销待办必须填写理由")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            task = conn.execute("SELECT * FROM review_tasks WHERE id=?", (task_id,)).fetchone()
            if not task:
                raise DomainError("复核待办不存在", 404)
            if task["status"] != "open":
                raise DomainError("待办已处理，不能撤销", 409)
            conn.execute(
                "UPDATE review_tasks SET status='revoked',revoked_by=?,revoked_at=?,revoke_reason=? WHERE id=?",
                (actor, utcnow(), reason.strip(), task_id),
            )
            self._audit(conn, actor, "review_task.revoked", {"task_id": task_id, "reason": reason.strip()})
            return dict(conn.execute("SELECT * FROM review_tasks WHERE id=?", (task_id,)).fetchone())

    def list_review_tasks(self, actor: str, role: str, status: str | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        if role not in SENSITIVE_ROLES:
            raise DomainError("角色无权查看复核待办", 403)
        with self.connect() as conn:
            if status:
                rows = conn.execute("SELECT * FROM review_tasks WHERE status=? ORDER BY id DESC", (status.strip(),)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM review_tasks ORDER BY id DESC").fetchall()
            return {"review_tasks": [dict(r) for r in rows]}

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
            match_score, match = self._screen(conn, counterparty_name.strip(), country)
            base_risk = customer["risk_score"]
            reason = "normal"
            if match:
                risk, reason = max(match_score, base_risk), "sanctions_match:%s:%s" % (match["list_name"], match["entry_name"])
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
            elif match:
                status = "escalated"
            elif risk >= 0.5:
                status = "review"
            else:
                status = "allowed"
            if customer["allowlisted"] and risk < 0.8 and amount <= 200000:
                status, risk, reason = "allowed", min(risk, 0.1), "allowlist_false_positive_reduction"
            latest_snap = conn.execute("SELECT id FROM watchlist_snapshots ORDER BY id DESC LIMIT 1").fetchone()
            screened_snapshot_id = latest_snap["id"] if latest_snap else None
            match_details_json = json.dumps(match, ensure_ascii=False) if match else None
            try:
                cur = conn.execute(
                    """INSERT INTO transactions(txn_ref,customer_id,entity_id,amount,currency,counterparty_name,
                       counterparty_country,status,risk_score,reason,created_by,created_at,
                       screened_snapshot_id,match_snapshot_id,match_entry_id,match_details)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (txn_ref.strip(), customer["id"], entity["id"], amount, currency.strip().upper(),
                     counterparty_name.strip(), country, status, risk, reason, actor, utcnow(),
                     screened_snapshot_id, match["snapshot_id"] if match else None,
                     match["entry_id"] if match else None, match_details_json),
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
                        """INSERT INTO alerts(fingerprint,entity_id,transaction_id,reason,risk_score,first_seen,last_seen,snapshot_id,match_details)
                           VALUES(?,?,?,?,?,?,?,?,?)""",
                        (fingerprint, entity["id"], cur.lastrowid, reason, risk, utcnow(), utcnow(),
                         match["snapshot_id"] if match else None, match_details_json),
                    )
                    alert_id = alert_cur.lastrowid
                alert = dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
            if entity["frozen"]:
                conn.execute("UPDATE transactions SET status='blocked' WHERE entity_id=? AND status='review'", (entity["id"],))
            audit_details = {"txn_ref": txn_ref, "status": status, "reason": reason}
            if match:
                audit_details["sanctions_basis"] = {
                    "snapshot_id": match["snapshot_id"], "snapshot_version": match["snapshot_version"],
                    "list_name": match["list_name"], "entry_name": match["entry_name"], "score": match["score"],
                }
            self._audit(conn, actor, "transaction.ingested", audit_details, entity["id"])
            transaction = dict(conn.execute("SELECT * FROM transactions WHERE id=?", (cur.lastrowid,)).fetchone())
            return {"transaction": transaction, "alert": alert, "resolved_entity_id": entity["id"]}

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
            return {"case": dict(case), "notes": notes}

    def state(self, actor: str = "", role: str = "viewer") -> dict[str, Any]:
        if role not in SENSITIVE_ROLES:
            return {"entities": [], "transactions": [], "alerts": [], "cases": [], "timeline": [],
                    "snapshots": [], "review_tasks": [], "access_limited": True}
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
            snapshots = [dict(r) for r in conn.execute("SELECT * FROM watchlist_snapshots ORDER BY id DESC LIMIT 50").fetchall()]
            review_tasks = [dict(r) for r in conn.execute("SELECT * FROM review_tasks ORDER BY id DESC LIMIT 100").fetchall()]
        return {"entities": entities, "transactions": transactions, "alerts": alerts, "cases": cases,
                "timeline": timeline, "snapshots": snapshots, "review_tasks": review_tasks, "access_limited": False}

    def seed_demo(self) -> dict[str, Any]:
        with self.connect() as conn:
            if conn.execute("SELECT COUNT(*) AS c FROM entities").fetchone()["c"]:
                return {"seeded": False, "reason": "已有数据"}
        entity = self.create_entity("analyst-demo", "analyst", "organization", "海岳贸易有限公司", ["海岳贸易"])
        customer = self.create_customer("analyst-demo", "analyst", entity["id"], "CUST-0001", "CN", "贸易", False, 0.2)
        self.add_or_update_watchlist("sup-demo", "supervisor", "OFAC", "海岳贸易有限公司", ["CN"])
        result = self.ingest_transaction("analyst-demo", "analyst", "TXN-DEMO-0001", customer["id"], 150000, "USD", "海岳贸易有限公司", "CN")
        return {"seeded": True, "entity_id": entity["id"], "customer_id": customer["id"], "alert_id": result["alert"]["id"] if result["alert"] else None}


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
            elif path == "/api/watchlist/snapshots":
                self._send(200, self.service.list_snapshots(actor, role))
            elif path == "/api/review-tasks":
                self._send(200, self.service.list_review_tasks(actor, role))
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
            elif path == "/api/watchlist/snapshots":
                result = self.service.publish_watchlist_snapshot(actor, role, **data)
            elif path == "/api/watchlist/nightly-review":
                result = self.service.run_nightly_review(actor, role, **data)
            elif path == "/api/review-tasks/revoke":
                result = self.service.revoke_review_task(actor, role, **data)
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
