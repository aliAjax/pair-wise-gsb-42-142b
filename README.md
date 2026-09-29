# 金融犯罪调查与制裁筛查系统

标准库实现的交易筛查、可疑线索、案件调查、实体合并、冻结和监管报告原型，数据保存到 SQLite。

## 运行

要求 Python 3.11+（当前 Python 3.9 环境亦可）。

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8208`，默认数据库 `financial_crime.db`。可用 `--db`、`--host`、`--port` 修改。

## 主要接口

请求头 `X-User`、`X-Role`。角色有 `analyst`、`investigator`、`supervisor`、`director`、`auditor`。

- `GET /health`、`GET /api/state`、`GET /api/cases/{id}`
- `POST /api/entities`、`POST /api/entities/alias`、`POST /api/entities/merge`
- `POST /api/customers`
- `POST /api/watchlist/publish`：主管按批次发布完整、不可变的名单快照（推荐）
- `POST /api/watchlist`：[兼容] 旧逐条维护，写草稿后自动发布新版本快照
- `GET /api/snapshots?list_name=`、`GET /api/snapshots/{id}`：查询历史快照及条目
- `POST /api/transactions`：按入账时最新快照筛查，交易留档快照版本与命中明细
- `POST /api/reviews/night-run`：夜间用新快照复核历史交易，生成可撤销待办
- `GET /api/reviews?status=open|resolved|all`：复核待办查询
- `POST /api/reviews/resolve`：处置待办（confirm/dismiss/escalate），已有案件只追加复核记录
- `POST /api/alerts/triage`：误报关闭或形成案件
- `POST /api/cases/update`、`POST /api/cases/report`
- `POST /api/entities/freeze`、`POST /api/entities/unfreeze`

## 名单版本模型

- 名单以批次为单位发布为不可变快照（`watchlist_snapshots` + `watchlist_snapshot_entries`），快照带版本号、内容哈希、发布人、时间和说明；内容与历史版本完全相同时拒绝重复发布。
- 交易入账时在同一事务内读取各名单「当前最新已发布版本」，把基线版本、每个名单的命中候选及最终命中的快照 ID/条目序号/相似度写入 `transactions.screen_detail`。此后发布新名单不会改变这笔交易当时的依据。
- 夜间复核（`run_night_review`）只用新快照重算并生成 `review_tasks`：`new_hit` / `hit_cleared` / `hit_changed`。原交易、原线索（alerts）、原案件字段一律不改；被更新版本取代的未决待办标记为 `revoked` 并在新待办上挂接 `superseded_task_id`，同一复核重复执行幂等。
- 处置待办时，若案件已存在则仅向 `case_reviews` 追加一条不可变复核记录并同步追加案件备注；无案件且选择升级时才新建案件。
- 发布在单个 SQLite 事务内完成（批次头与条目同提交），服务中断后重启会清理残留的 `publishing` 半成品批次，不影响已发布版本与后续版本号。
- 首次启动时，旧 `watchlist` 逐条活表中每个名单的现有有效条目自动冻结为该名单的 v1 历史快照（`origin=migration`）。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

测试覆盖制裁命中到监管报告、冻结即时阻断、实体合并迁移、线索降噪、案件保密和版本冲突，以及快照不可变与入账留档、夜间复核不改原件、待办撤销与幂等、旧名单迁移为 v1、半成品批次崩溃恢复。

## 局限

名称筛查使用归一化和序列相似度，不替代专业名单供应商；快照不可变性由应用层与 SQLite 事务保证（没有 WORM 存储或外部签名）；冻结仅影响本系统内后续交易；金额与风险规则是演示规则；身份依赖请求头，没有密钥管理、数字签名或真实监管报送通道。
