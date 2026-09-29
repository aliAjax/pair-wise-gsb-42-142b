import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import FinancialCrimeService, DomainError  # noqa: E402


class SnapshotScreeningTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = FinancialCrimeService(Path(self.tmp.name) / "snapshot.db")
        self.entity = self.service.create_entity("analyst1", "analyst", "organization", "远海贸易", ["远海"])
        self.customer = self.service.create_customer("analyst1", "analyst", self.entity["id"], "C-100", "CN", risk_score=0.2)

    def tearDown(self):
        self.tmp.cleanup()

    def _txn(self, ref, name="远海贸易", country="CN", amount=150000):
        return self.service.ingest_transaction(
            "analyst1", "analyst", ref, self.customer["id"], amount, "USD", name, country
        )

    def test_publish_immutable_snapshot_and_txn_archives_version(self):
        v1 = self.service.publish_watchlist(
            "sup1", "supervisor", "OFAC",
            [{"name": "远海贸易", "countries": ["CN"]}],
            note="第一版",
        )
        self.assertEqual(1, v1["version"])
        self.assertEqual("published", v1["status"])
        result = self._txn("T-100")
        txn = result["transaction"]
        self.assertEqual("escalated", txn["status"])
        self.assertEqual(v1["id"], txn["screen_snapshot_id"])
        detail = json.loads(txn["screen_detail"])
        self.assertEqual({"OFAC": 1}, detail["baseline_versions"])
        self.assertEqual("远海贸易", detail["match"]["entry_name"])
        self.assertEqual(v1["id"], detail["match"]["snapshot_id"])

        # 发布第二版：条目改名，旧交易的依据不能被改写
        v2 = self.service.publish_watchlist(
            "sup1", "supervisor", "OFAC",
            [{"name": "远海贸易集团", "countries": ["CN"]}],
            note="第二版",
        )
        self.assertEqual(2, v2["version"])
        with self.service.connect() as conn:
            stale = conn.execute(
                "SELECT * FROM watchlist_snapshot_entries WHERE snapshot_id=?",
                (v1["id"],),
            ).fetchall()
        self.assertEqual("远海贸易", stale[0]["name"])
        with self.service.connect() as conn:
            kept = conn.execute("SELECT * FROM transactions WHERE txn_ref='T-100'").fetchone()
            entries_v1 = conn.execute(
                "SELECT name FROM watchlist_snapshot_entries WHERE snapshot_id=?", (v1["id"],)
            ).fetchall()
        self.assertEqual(v1["id"], kept["screen_snapshot_id"])
        self.assertEqual("远海贸易", entries_v1[0]["name"])
        self.assertEqual(1, json.loads(kept["screen_detail"])["match"]["snapshot_version"])

    def test_identical_batch_is_rejected(self):
        self.service.publish_watchlist("sup1", "supervisor", "OFAC",
                                       [{"name": "远海贸易", "countries": ["CN"]}])
        with self.assertRaises(DomainError) as ctx:
            self.service.publish_watchlist("sup1", "supervisor", "OFAC",
                                           [{"name": "远海贸易", "countries": ["CN"]}])
        self.assertEqual(409, ctx.exception.status)

    def test_night_review_creates_revocable_tasks_and_never_rewrites_originals(self):
        self.service.publish_watchlist("sup1", "supervisor", "OFAC",
                                       [{"name": "远海贸易", "countries": ["CN"]}])
        ingested = self._txn("T-200")
        txn_before = dict(ingested["transaction"])
        alert_before = dict(ingested["alert"])
        case = self.service.triage_alert(
            "inv1", "investigator", alert_before["id"], "escalate", "inv1", "CASE-200"
        )["case"]
        case_version_before = case["version"]
        with self.service.connect() as conn:
            alert_before = dict(conn.execute(
                "SELECT * FROM alerts WHERE id=?", (alert_before["id"],)
            ).fetchone())

        # 新快照：原命中消失
        self.service.publish_watchlist("sup1", "supervisor", "OFAC",
                                       [{"name": "完全无关的海外银行", "countries": ["KP"]}])
        review = self.service.run_night_review("sup1", "supervisor")
        self.assertEqual(1, len(review["created"]))
        task_id = review["created"][0]["task_id"]
        self.assertEqual("hit_cleared", review["created"][0]["change_type"])

        # 原交易、原线索、原案件状态不被改写
        with self.service.connect() as conn:
            txn_after = dict(conn.execute("SELECT * FROM transactions WHERE id=?", (txn_before["id"],)).fetchone())
            alert_after = dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_before["id"],)).fetchone())
            case_after = dict(conn.execute("SELECT * FROM cases WHERE id=?", (case["id"],)).fetchone())
        self.assertEqual(txn_before["status"], txn_after["status"])
        self.assertEqual(txn_before["screen_snapshot_id"], txn_after["screen_snapshot_id"])
        self.assertEqual(alert_before["status"], alert_after["status"])
        self.assertEqual(case_version_before, case_after["version"])

        # 又发布一版：原名单重新列名（同名但新版本），旧的未决待办被撤销并挂接 superseded
        self.service.publish_watchlist("sup1", "supervisor", "OFAC",
                                       [{"name": "远海贸易", "countries": ["CN"]},
                                        {"name": "远海贸易有限公司", "countries": ["CN"]}],
                                       note="重新列名并新增条目")
        review2 = self.service.run_night_review("sup1", "supervisor")
        self.assertIn(task_id, review2["revoked"])
        self.assertEqual(1, len(review2["created"]))
        new_task_id = review2["created"][0]["task_id"]
        self.assertEqual("hit_changed", review2["created"][0]["change_type"])
        with self.service.connect() as conn:
            old_task = conn.execute("SELECT * FROM review_tasks WHERE id=?", (task_id,)).fetchone()
            new_task = conn.execute("SELECT * FROM review_tasks WHERE id=?", (new_task_id,)).fetchone()
        self.assertEqual("revoked", old_task["status"])
        self.assertEqual(task_id, new_task["superseded_task_id"])

        # 处置新待办：已有案件只追加复核记录
        resolved = self.service.resolve_review_task(
            "inv1", "investigator", new_task_id, "confirm", "夜间复核确认仍命中"
        )
        self.assertEqual(case["id"], resolved["case_id"])
        case_detail = self.service.get_case("inv1", "investigator", case["id"])
        self.assertEqual(1, len(case_detail["reviews"]))
        review_row = case_detail["reviews"][0]
        self.assertEqual(new_task_id, review_row["task_id"])
        self.assertEqual("hit_changed", review_row["change_type"])
        # 复核记录只追加：案件版本不因复核本身跳变，原始案件数据仍在
        self.assertEqual(1, len(case_detail["notes"]))
        self.assertIn("名单复核", case_detail["notes"][0]["note"])
        # 已处理的待办不能重复处置
        with self.assertRaises(DomainError) as ctx:
            self.service.resolve_review_task("inv1", "investigator", new_task_id, "dismiss", "重复处理")
        self.assertEqual(409, ctx.exception.status)

    def test_night_review_is_idempotent_on_same_snapshot(self):
        self.service.publish_watchlist("sup1", "supervisor", "OFAC",
                                       [{"name": "远海贸易", "countries": ["CN"]}])
        self._txn("T-300")
        self.service.publish_watchlist("sup1", "supervisor", "OFAC",
                                       [{"name": "完全无关的海外银行", "countries": ["KP"]}])
        first = self.service.run_night_review("sup1", "supervisor")
        second = self.service.run_night_review("sup1", "supervisor")
        self.assertEqual(1, len(first["created"]))
        self.assertEqual(0, len(second["created"]))

    def test_review_escalate_without_case_creates_case_and_appends_review(self):
        self.service.publish_watchlist("sup1", "supervisor", "OFAC",
                                       [{"name": "远海贸易", "countries": ["CN"]}])
        self._txn("T-400", amount=10000)  # 制裁命中仍 escalated
        self.service.publish_watchlist("sup1", "supervisor", "OFAC",
                                       [{"name": "远海贸易", "countries": ["CN", "KP"]}])
        # 同名命中、版本不同 -> hit_changed 待办
        review = self.service.run_night_review("sup1", "supervisor")
        changes = {c["change_type"] for c in review["created"]}
        self.assertIn("hit_changed", changes)
        task_id = next(c["task_id"] for c in review["created"] if c["change_type"] == "hit_changed")
        resolved = self.service.resolve_review_task("sup1", "supervisor", task_id, "escalate", "升级调查")
        self.assertIsNotNone(resolved["case"])
        case_views = self.service.get_case("sup1", "supervisor", resolved["case_id"])
        self.assertEqual("hit_changed", case_views["reviews"][0]["change_type"])

    def test_legacy_row_by_row_watchlist_migrates_to_v1_snapshot(self):
        # 直接构造"旧版本"数据库：只有 watchlist 活表，没有任何快照
        import sqlite3
        db_path = Path(self.tmp.name) / "legacy.db"
        conn = sqlite3.connect(db_path)
        conn.executescript(
            """
            CREATE TABLE watchlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT, list_name TEXT NOT NULL, name TEXT NOT NULL,
                normalized_name TEXT NOT NULL, countries TEXT NOT NULL DEFAULT '[]', version INTEGER NOT NULL DEFAULT 1,
                active INTEGER NOT NULL DEFAULT 1, updated_by TEXT NOT NULL, updated_at TEXT NOT NULL,
                UNIQUE(list_name, normalized_name)
            );
            INSERT INTO watchlist(list_name,name,normalized_name,countries,version,updated_by,updated_at)
            VALUES('OFAC','旧名单实体','旧名单实体','["CN"]',3,'old-sup','2026-01-01T00:00:00+00:00');
            """
        )
        conn.commit()
        conn.close()
        service = FinancialCrimeService(db_path)
        with service.connect() as check:
            snap = check.execute(
                "SELECT * FROM watchlist_snapshots WHERE list_name='OFAC' ORDER BY version"
            ).fetchall()
            entries = check.execute(
                "SELECT name FROM watchlist_snapshot_entries WHERE snapshot_id=?", (snap[0]["id"],)
            ).fetchall()
        self.assertEqual(1, len(snap))
        self.assertEqual(1, snap[0]["version"])
        self.assertEqual("migration", snap[0]["origin"])
        self.assertEqual("旧名单实体", entries[0]["name"])
        # 重启不应重复迁移
        service2 = FinancialCrimeService(db_path)
        with service2.connect() as check:
            count = check.execute("SELECT COUNT(*) AS c FROM watchlist_snapshots").fetchone()["c"]
        self.assertEqual(1, count)

    def test_legacy_incremental_api_auto_publishes_batches(self):
        self.service.add_or_update_watchlist("sup1", "supervisor", "OFAC", "远海贸易", ["CN"])
        self._txn("T-500")
        # 停用条目 -> 下一版快照为空名单，夜间复核给出 hit_cleared
        self.service.add_or_update_watchlist(
            "sup1", "supervisor", "OFAC", "远海贸易", ["CN"], active=False
        )
        review = self.service.run_night_review("sup1", "supervisor")
        self.assertIn("hit_cleared", {c["change_type"] for c in review["created"]})
        snaps = self.service.list_snapshots("sup1", "supervisor", "OFAC")["snapshots"]
        self.assertEqual([1, 2], [s["version"] for s in snaps])

    def test_no_half_finished_batch_after_crash_recovery(self):
        # 模拟崩溃残留：snapshot 头写了但批次未完成
        self.service.publish_watchlist("sup1", "supervisor", "OFAC",
                                       [{"name": "远海贸易", "countries": ["CN"]}])
        with self.service.connect() as conn:
            cur = conn.execute(
                """INSERT INTO watchlist_snapshots(list_name,version,status,content_hash,entry_count,
                   published_by,published_at,note,origin)
                   VALUES('OFAC',9,'publishing','sha256:stale',0,'sup1','2026-09-29T00:00:00+00:00','','published')"""
            )
            stale_id = cur.lastrowid
            conn.execute(
                "INSERT INTO watchlist_snapshot_entries(snapshot_id,list_name,version,seq,name,normalized_name,countries)"
                " VALUES(?,'OFAC',9,1,'残留','残留','[]')",
                (stale_id,),
            )
        # 重新初始化（模拟服务重启）：半成品批次被清掉，正式版本不受影响
        service = FinancialCrimeService(Path(self.tmp.name) / "snapshot.db")
        with service.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM watchlist_snapshots WHERE status='published' ORDER BY version"
            ).fetchall()
            stale_entries = conn.execute(
                "SELECT * FROM watchlist_snapshot_entries WHERE snapshot_id=?", (stale_id,)
            ).fetchall()
        self.assertEqual([1], [r["version"] for r in rows])
        self.assertEqual(0, len(stale_entries))
        # 清理后下一次发布版本号不能撞上残留的 9
        v2 = service.publish_watchlist("sup1", "supervisor", "OFAC",
                                       [{"name": "远海贸易", "countries": ["CN", "KP"]}])
        self.assertEqual(2, v2["version"])

    def test_screening_uses_snapshot_read_point_under_concurrent_publish(self):
        self.service.publish_watchlist("sup1", "supervisor", "OFAC",
                                       [{"name": "远海贸易", "countries": ["CN"]}])
        # 入账进行期间发布新名单：新交易要么全量按 v1，要么全量按 v2，不能混用
        self.service.publish_watchlist("sup1", "supervisor", "OFAC",
                                       [{"name": "远海贸易集团股份公司", "countries": ["CN"]}])
        txn = self.service.ingest_transaction(
            "analyst1", "analyst", "T-600", self.customer["id"], 150000, "USD", "远海贸易", "CN"
        )["transaction"]
        detail = json.loads(txn["screen_detail"])
        self.assertEqual({"OFAC": 2}, detail["baseline_versions"])
        self.assertNotIn("match", detail)  # v2 名称不再匹配，历史 v1 依据不可被"复活"

    def test_only_supervisor_publishes(self):
        with self.assertRaises(DomainError) as ctx:
            self.service.publish_watchlist("analyst1", "analyst", "OFAC",
                                           [{"name": "远海贸易", "countries": ["CN"]}])
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(DomainError) as ctx:
            self.service.run_night_review("analyst1", "analyst")
        self.assertEqual(403, ctx.exception.status)


if __name__ == "__main__":
    unittest.main()
