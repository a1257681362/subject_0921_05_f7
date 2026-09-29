# 对外开放加工单查询 —— HMAC 签名协议与验收

对外只读接口前缀 `/open/api/**`，免 Shiro Basic，改用无状态 HMAC-SHA256 签名鉴权：
参数排序后签名、±15 分钟时间窗、nonce 30 分钟落库防重放、验签失败只回专用码不暴露细节。

## 1. 开放接口（仅 GET 只读）

| 接口 | 说明 |
| --- | --- |
| `GET /open/api/orders/by-no/{orderNo}` | 按加工单号查详情（主单+有效处方+状态流转+返修） |
| `GET /open/api/orders/{id}` | 按主键查详情 |
| `GET /open/api/orders?status=&storeCode=` | 列表，可按状态/门店过滤 |

不提供任何写接口。返回体结构与内部接口一致：`{ success, code, message, data }`。

## 2. 请求头

| 头 | 说明 |
| --- | --- |
| `X-Access-App` | 接入方 appId（服务端在 `evops.openapi.apps` 登记 appId→secret） |
| `X-Timestamp` | 发起时间，**epoch 毫秒**。与服务端时钟偏差超过 15 分钟拒收 |
| `X-Nonce` | 一次性随机串，8~64 位 `[A-Za-z0-9_-]`，30 分钟内同一 appId 不可重复 |
| `X-Signature` | HMAC-SHA256 摘要，**十六进制小写** |

## 3. 待签名串

```
METHOD + "\n" + requestURI(不含 query) + "\n" + timestamp + "\n" + nonce + "\n" + canonicalQuery
```

`canonicalQuery`（"参数排序后签名"）：

1. 取全部 query 参数（同名参数取全部值）；
2. 按 key 字典序排序，同 key 按 value 字典序排序；
3. 每个 key/value 做 RFC3986 百分号编码（unreserved `A-Za-z0-9-_.~` 不编码，
   空格为 `%20`，其余字节按 UTF-8 编码、百分号**大写**，如"张"=`%E5%BC%A0`）；
4. 以 `k=v&k=v` 拼接；无参数为空串。

要点：参数**发送顺序任意**（服务端重排后验签），但任何值被篡改都会导致签名不符。
body 不参与签名（仅开放 GET）。

curl/openssl 计算示例：

```sh
TS=$(date +%s%3N)
NONCE=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
CANON="status=CREATED&storeCode=S01"          # 已按 key 字典序
SIGN=$(printf 'GET\n/open/api/orders\n%s\n%s\n%s' "$TS" "$NONCE" "$CANON" \
       | openssl dgst -sha256 -hmac "$APP_SECRET" | awk '{print $NF}')
curl "$BASE_URL/open/api/orders?storeCode=S01&status=CREATED" \   # 乱序发送也通过
  -H "X-Access-App: $APP_ID" -H "X-Timestamp: $TS" \
  -H "X-Nonce: $NONCE" -H "X-Signature: $SIGN"
```

## 4. 失败码（HTTP 401，文案固定，不含任何细节）

| code | message | 触发情形 |
| --- | --- | --- |
| `SIGN_INVALID` | 请求签名校验未通过 | 头缺失/格式非法、未知 appId、签名不符（含参数篡改） |
| `SIGN_EXPIRED` | 请求已超出允许的时间窗口 | 时间戳早于或晚于服务端 15 分钟 |
| `NONCE_DUPLICATED` | 请求不可重复提交 | 同一 appId 的 nonce 在 30 分钟内重复 |

鉴权通过后的业务错误（如 `ORDER_NOT_FOUND`）仍走统一结构、HTTP 200。
具体失败原因只写服务端 warn 日志（带 traceId），响应体不区分"缺哪个头/哪一段不对"。

## 5. nonce 清理

`t_openapi_nonce` 按 `(app_id, nonce)` 唯一约束判重，重复直接拒绝；
`expire_time = 入库 + 30 分钟`，定时任务每分钟第 43 秒物理清理到期行，启动时补扫一次。
**保留窗口 30 分钟 > 签名时间窗 15 分钟**，因此清理不可能在时间窗内提前删掉仍可被重放的 nonce。
该表与 `t_batch_job` 同属全库"禁止物理删除"约定的运维临时数据例外。

## 6. 验收当天：跑两轮

前置：服务已启动（`mvn spring-boot:run`），且 appId/secret 已在配置登记。

```sh
APP_ID=demo-partner APP_SECRET=dev-only-please-override sh scripts/openapi-acceptance.sh
```

脚本自动造一单数据并跑六个用例，逐条打印 PASS/FAIL，全过退出码 0：

1. 正常签名按单号查询 → 200 / `OK`
2. query 参数乱序发送 → 200 / `OK`（canonical 重排验签）
3. 时间戳早 16 分钟 → 401 / `SIGN_EXPIRED`
4. 同一 nonce 连发两次 → 首次 OK，第二次 401 / `NONCE_DUPLICATED`
5. 签名错误 → 401 / `SIGN_INVALID`
6. 缺签名头 → 401 / `SIGN_INVALID`

**验收当天执行两轮：第一轮现场看输出；第二轮同一命令全程录屏。**
两轮均 `PASS=6 FAIL=0` 为通过。
