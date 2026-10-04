# 山火事件指挥与离线人员调度

维护火线、风向、资源和任务区，合并离线现场记录并防止人员重复分配。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8319
```

默认端口为`8319`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`（关闭`closed`不在此通道，见下）
- `GET /api/audit?item_id=...`

### 观察—关闭签认—角色交接（一套版本联动）

两张“窗口”各有单调递增版本，关闭签认同时绑定观察版本与交接版本：

- `POST /api/items/{id}/observation`（field_commander）：建立/更新任务区观察窗口（任务区、八方位风向、风速）。
  窗口每次更新版本+1，**所有未完成签认（pending/active）立即失效**。
- `POST /api/items/{id}/handover`（incident_commander）：把关闭权限交给副指挥，body含`to_actor`、
  `to_role=deputy_commander`、`reason`。交接版本+1并**立即作废旧签认**，交接双方写入审计链。
- `POST /api/items/{id}/signoffs`：当前持权人提交关闭签认（pending）。
  交班后原人员的旧审批、或角色不在当前窗口内的提交，一律**按越权拒绝（403）**，
  拒绝记录（rejected + 失败原因）和审计事件都会落库。
- `POST /api/items/{id}/signoffs/{sid}/confirm`：当前持权人二次确认，pending→active。
  确认时若窗口版本已变，签认置为 invalidated（失败原因可见）并要求重新提交。
- `POST /api/items/{id}/signoffs/close`：body含`signoff_id`，仅当该签认为 active
  且观察/交接版本与当前窗口一致时才能关闭；风向再变等导致“依据失真”时返回409并把签认置失效。
- `GET /api/items/{id}/signoffs`：返回观察窗口、当前持权人、**当前有效签认**、
  全部签认（含 failure_reason/触发来源）及审计链校验结果。

规则：必须先建立观察窗口才能签认；火场须推进到 controlled 且无 open 记录方可关闭；
观察更新、交接、提交、拒绝、确认、失效、关闭的每一次处理都追加到**同一条 SHA-256 哈希审计链**。
演示页（根路径 `/`）可一键演练“夜班交接后旧审批被拒 → 风向再变使依据失真 → 重新确认关闭”。

允许角色：field_commander, incident_commander, deputy_commander, logistics, viewer。火线长度、风向变化和离线记录数量影响风险等级；同一资源不能同时出现在多个活动任务中。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
