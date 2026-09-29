import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import DomainError, FinancialCrimeService  # noqa: E402


class WatchlistSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = FinancialCrimeService(Path(self.tmp.name) / "snap.db")
        self.entity = self.service.create_entity("analyst1", "analyst", "organization", "远海贸易", ["远海"])
        self.customer = self.service.create_customer("analyst1", "analyst", self.entity["id"], "C-001", "CN", risk_score=0.2)

    def tearDown(self):
        self.tmp.cleanup()

    def test_publish_immutable_snapshot_and_record_hit_basis(self):
        snap = self.service.publish_watchlist_snapshot(
            "sup1", "supervisor", "OFAC",
            [{"name": "远海贸易", "countries": ["CN"], "entry_ref": "OFAC-001"}],
            note="首批",
        )
        self.assertEqual(1, snap["version"])
        self.assertEqual(1, snap["entry_count"])
        self.assertTrue(snap["checksum"])
        ingested = self.service.ingest_transaction(
            "analyst1", "analyst", "T-100", self.customer["id"], 1000, "USD", "远海贸易", "CN"
        )
        txn = ingested["transaction"]
        self.assertEqual("escalated", txn["status"])
        self.assertEqual(snap["id"], txn["match_snapshot_id"])
        self.assertEqual(snap["entries"][0]["id"], txn["match_entry_id"])
        details = json.loads(txn["match_details"])
        self.assertEqual(snap["id"], details["snapshot_id"])
        self.assertEqual(1, details["snapshot_version"])
        self.assertEqual("OFAC", details["list_name"])
        self.assertEqual("远海贸易", details["entry_name"])
        # 快照不可变：再次发布生成新版本，旧版本保持不变
        snap2 = self.service.publish_watchlist_snapshot(
            "sup1", "supervisor", "OFAC",
            [{"name": "远海贸易", "countries": ["CN"]}, {"name": "北方工业", "countries": ["CN"]}],
        )
        self.assertEqual(2, snap2["version"])
        self.assertNotEqual(snap["checksum"], snap2["checksum"])
        old = self.service.list_snapshots("sup1", "supervisor", "OFAC")["snapshots"]
        v1 = [s for s in old if s["version"] == 1][0]
        self.assertEqual(1, v1["entry_count"])  # 旧快照条目不变

    def test_nightly_review_creates_revocable_todo_without_rewriting_transaction(self):
        # 首批只含远海贸易
        self.service.publish_watchlist_snapshot("sup1", "supervisor", "OFAC",
                                                [{"name": "远海贸易", "countries": ["CN"]}])
        # 一笔当时合法的交易：普通供应商（不在首批名单）
        entity2 = self.service.create_entity("analyst1", "analyst", "organization", "普通供应商", [])
        customer2 = self.service.create_customer("analyst1", "analyst", entity2["id"], "C-002", "US", risk_score=0.1)
        allowed = self.service.ingest_transaction("analyst1", "analyst", "T-200", customer2["id"], 500, "USD", "普通供应商", "US")
        self.assertEqual("allowed", allowed["transaction"]["status"])
        # 第二批新增普通供应商
        self.service.publish_watchlist_snapshot("sup1", "supervisor", "OFAC",
                                                [{"name": "远海贸易", "countries": ["CN"]},
                                                 {"name": "普通供应商", "countries": ["US"]}])
        review = self.service.run_nightly_review("sup1", "supervisor")
        self.assertEqual(1, len(review["tasks_created"]))
        task = review["tasks_created"][0]
        self.assertEqual("open", task["status"])
        self.assertEqual(allowed["transaction"]["id"], task["transaction_id"])
        self.assertEqual("普通供应商", task["entry_name"])
        # 原交易与原线索不被改写
        unchanged = [t for t in self.service.state("sup1", "supervisor")["transactions"]
                     if t["id"] == allowed["transaction"]["id"]][0]
        self.assertEqual("allowed", unchanged["status"])
        self.assertIsNone(unchanged["match_snapshot_id"])
        # 待办可撤销
        revoked = self.service.revoke_review_task("sup1", "supervisor", task["id"], "误报，已核实")
        self.assertEqual("revoked", revoked["status"])
        self.assertEqual("sup1", revoked["revoked_by"])
        with self.assertRaises(DomainError) as ctx:
            self.service.revoke_review_task("sup1", "supervisor", task["id"], "再次撤销")
        self.assertEqual(409, ctx.exception.status)

    def test_nightly_review_appends_note_to_existing_case_only(self):
        self.service.publish_watchlist_snapshot("sup1", "supervisor", "OFAC",
                                                [{"name": "远海贸易", "countries": ["CN"]}])
        # 北方工业当时是大额审查（有线索），成案
        entity3 = self.service.create_entity("analyst1", "analyst", "organization", "北方工业", [])
        customer3 = self.service.create_customer("analyst1", "analyst", entity3["id"], "C-003", "CN", risk_score=0.2)
        flagged = self.service.ingest_transaction("analyst1", "analyst", "T-300", customer3["id"], 150000, "USD", "北方工业", "CN")
        case = self.service.triage_alert("inv1", "investigator", flagged["alert"]["id"], "escalate", "inv1", "CASE-300")["case"]
        # 第二批新增北方工业
        self.service.publish_watchlist_snapshot("sup1", "supervisor", "OFAC",
                                                [{"name": "远海贸易", "countries": ["CN"]},
                                                 {"name": "北方工业", "countries": ["CN"]}])
        review = self.service.run_nightly_review("sup1", "supervisor")
        self.assertEqual(0, len(review["tasks_created"]))  # 已有案件，不生成待办
        self.assertEqual(1, len(review["cases_appended"]))
        self.assertEqual(case["id"], review["cases_appended"][0]["case_id"])
        full = self.service.get_case("inv1", "investigator", case["id"])
        self.assertEqual(1, len(full["notes"]))
        self.assertIn("夜间复核", full["notes"][0]["note"])
        # 案件本身未被改写（状态、版本不变）
        self.assertEqual(case["version"], full["case"]["version"])
        self.assertEqual(case["status"], full["case"]["status"])

    def test_nightly_review_skips_already_recorded_entity(self):
        self.service.publish_watchlist_snapshot("sup1", "supervisor", "OFAC",
                                                [{"name": "远海贸易", "countries": ["CN"]}])
        ingested = self.service.ingest_transaction("analyst1", "analyst", "T-400", self.customer["id"], 1000, "USD", "远海贸易", "CN")
        self.assertEqual("escalated", ingested["transaction"]["status"])
        # 后续快照仍含同一实体，仅版本推进
        self.service.publish_watchlist_snapshot("sup1", "supervisor", "OFAC",
                                                [{"name": "远海贸易", "countries": ["CN"]}, {"name": "其他公司", "countries": ["US"]}])
        review = self.service.run_nightly_review("sup1", "supervisor")
        self.assertEqual(0, len(review["tasks_created"]))
        self.assertEqual(0, len(review["cases_appended"]))

    def test_publish_is_atomic_on_failure(self):
        before = len(self.service.list_snapshots("sup1", "supervisor")["snapshots"])
        with self.assertRaises(DomainError):
            self.service.publish_watchlist_snapshot("sup1", "supervisor", "OFAC", [])
        after = len(self.service.list_snapshots("sup1", "supervisor")["snapshots"])
        self.assertEqual(before, after)  # 不留半成品批次
        with self.assertRaises(DomainError) as ctx:
            self.service.publish_watchlist_snapshot("sup1", "supervisor", "OFAC",
                                                    [{"name": "X", "countries": []}], expected_version=99)
        self.assertEqual(409, ctx.exception.status)
        with self.assertRaises(DomainError) as ctx2:
            self.service.publish_watchlist_snapshot("analyst1", "analyst", "OFAC", [{"name": "Y"}])
        self.assertEqual(403, ctx2.exception.status)

    def test_legacy_watchlist_migrates_to_first_snapshot(self):
        tmp = tempfile.TemporaryDirectory()
        db_path = Path(tmp.name) / "legacy.db"
        conn = sqlite3.connect(db_path)
        conn.execute("""CREATE TABLE watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT, list_name TEXT, name TEXT, normalized_name TEXT,
            countries TEXT, version INTEGER, active INTEGER, updated_by TEXT, updated_at TEXT)""")
        conn.execute(
            "INSERT INTO watchlist(list_name,name,normalized_name,countries,version,active,updated_by,updated_at) VALUES(?,?,?,?,?,?,?,?)",
            ("OFAC", "旧名单公司", "旧名单公司", '["CN"]', 1, 1, "sup1", "2026-01-01T00:00:00+00:00"),
        )
        conn.commit()
        conn.close()
        service = FinancialCrimeService(db_path)
        snaps = service.list_snapshots("sup1", "supervisor")["snapshots"]
        self.assertEqual(1, len(snaps))
        self.assertEqual(1, snaps[0]["version"])
        self.assertEqual(1, snaps[0]["entry_count"])
        self.assertEqual("旧名单公司", snaps[0]["entries"][0]["name"])
        # 迁移后的快照参与筛查
        entity = service.create_entity("analyst1", "analyst", "organization", "旧名单公司", [])
        customer = service.create_customer("analyst1", "analyst", entity["id"], "C-900", "CN", risk_score=0.1)
        ingested = service.ingest_transaction("analyst1", "analyst", "T-900", customer["id"], 100, "USD", "旧名单公司", "CN")
        self.assertEqual("escalated", ingested["transaction"]["status"])
        self.assertEqual(snaps[0]["id"], ingested["transaction"]["match_snapshot_id"])
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
