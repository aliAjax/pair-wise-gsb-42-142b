# 金融犯罪调查与制裁筛查系统

标准库实现的交易筛查、制裁名单不可变快照、夜间复核待办、可疑线索、案件调查、实体合并、冻结和监管报告原型，数据保存到 SQLite。

## 运行

要求 Python 3.11+（当前 Python 3.9 环境亦可）。

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8208`，默认数据库 `financial_crime.db`。可用 `--db`、`--host`、`--port` 修改。

## 制裁名单快照机制

名单不再逐条覆盖，而是按**批次发布不可变快照**：

- `POST /api/watchlist/snapshots`：按批次发布新快照（`list_name` + `entries`，含 `name`/`countries`/`entry_ref`）。每个名单独立递增版本，写入带校验和，单一事务提交——发布与入账并发时由 `BEGIN IMMEDIATE` 串行化，进程中断也只会整体回滚，**不留半成品批次**。
- `POST /api/watchlist`：旧的逐条维护入口保留兼容，底层改为在当前全量条目上发布一个新快照版本。
- `GET /api/watchlist/snapshots`：查看各名单的历史快照与条目。
- **入账留档**：`POST /api/transactions` 筛查时记录命中的快照版本（`match_snapshot_id`）、命中条目（`match_entry_id`）与明细（`match_details`），并记录筛查所依据的最新快照（`screened_snapshot_id`）。事后可随时说清“这笔交易当时依据哪版名单”。
- **夜间复核**：`POST /api/watchlist/nightly-review` 用最新快照重算全部历史交易，生成**可撤销的复核待办**（`review_tasks`）。复核**不改写原交易与原线索**；已有案件的交易只向案件**追加复核记录**（case note），不新建案件、不改案件状态。已依据同一制裁实体命中的交易不重复生成待办。
- `GET /api/review-tasks`、`POST /api/review-tasks/revoke`：查看与撤销复核待办（撤销不影响原交易）。
- **历史迁移**：旧的逐条名单表在首次启动时自动迁移为第一版历史快照（v1），迁移后即参与筛查。

## 主要接口

请求头 `X-User`、`X-Role`。角色有 `analyst`、`investigator`、`supervisor`、`director`、`auditor`。

- `GET /health`、`GET /api/state`、`GET /api/cases/{id}`
- `POST /api/entities`、`POST /api/entities/alias`、`POST /api/entities/merge`
- `POST /api/customers`
- `POST /api/watchlist`：旧逐条维护（底层发布快照）
- `POST /api/watchlist/snapshots`：按批次发布不可变名单快照
- `GET /api/watchlist/snapshots`：查看历史快照
- `POST /api/watchlist/nightly-review`：用最新快照生成可撤销复核待办
- `GET /api/review-tasks`、`POST /api/review-tasks/revoke`：查看/撤销复核待办
- `POST /api/transactions`：筛查并生成指纹去重后的线索，留档命中快照版本与明细
- `POST /api/alerts/triage`：误报关闭或形成案件
- `POST /api/cases/update`、`POST /api/cases/report`
- `POST /api/entities/freeze`、`POST /api/entities/unfreeze`

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖制裁命中到监管报告、冻结即时阻断、实体合并迁移、线索降噪、案件保密、版本冲突、不可变快照发布与入账留档、夜间复核待办的生成/撤销/已有案件追加记录、发布原子性，以及旧逐条名单迁移。

## 局限

名称筛查使用归一化和序列相似度，不替代专业名单供应商；冻结仅影响本系统内后续交易；金额与风险规则是演示规则；身份依赖请求头，没有密钥管理、数字签名或真实监管报送通道。
